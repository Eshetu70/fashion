/**
 * server.js (Node 18+)
 * - Serves frontend from /public
 * - API saves products.json in GitHub
 * - Uploads images as separate files in GitHub (/public/uploads)
 *
 * ENV:
 *  GITHUB_TOKEN
 *  GITHUB_USERNAME
 *  GITHUB_REPO
 *  PRODUCTS_FILE=products.json
 *  GITHUB_BRANCH=main
 *  ADMIN_API_KEY=...
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

if (typeof fetch !== "function") throw new Error("Use Node.js 18+ (global fetch required).");

const app = express();
app.use(cors());
app.options("*", cors());
app.use(express.json({ limit: "25mb" }));

// Serve frontend
const publicDir = path.join(__dirname, "public");
const indexFile = path.join(publicDir, "index.html");
app.use(express.static(publicDir));

app.get("/", (req, res) => {
  if (fs.existsSync(indexFile)) return res.sendFile(indexFile);
  res.status(200).send("Backend running, but public/index.html missing.");
});

app.get("/health", (req, res) => res.json({ ok: true }));

// ---- ENV ----
const PORT = process.env.PORT || 3000;

const {
  GITHUB_TOKEN,
  GITHUB_USERNAME,
  GITHUB_REPO,
  PRODUCTS_FILE = "products.json",
  GITHUB_BRANCH = "main",
  ADMIN_API_KEY,
} = process.env;

console.log("ENV CHECK:", {
  GITHUB_USERNAME: !!GITHUB_USERNAME,
  GITHUB_REPO: !!GITHUB_REPO,
  PRODUCTS_FILE,
  GITHUB_BRANCH,
  GITHUB_TOKEN: !!GITHUB_TOKEN,
  ADMIN_API_KEY: !!ADMIN_API_KEY,
});

const GH_API_BASE = "https://api.github.com";

// ---- Helpers ----
function requireAdmin(req, res, next) {
  const key = req.header("x-admin-key");
  if (!ADMIN_API_KEY) return res.status(500).json({ error: "Server missing ADMIN_API_KEY" });
  if (!key || key !== ADMIN_API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function ghHeaders() {
  if (!GITHUB_TOKEN) throw new Error("Missing GITHUB_TOKEN");
  return {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "fashion-backend",
  };
}

// ✅ IMPORTANT FIX: keep slashes, encode each segment only
function encodePath(filePath) {
  return filePath.split("/").map(encodeURIComponent).join("/");
}

function contentUrl(filePath) {
  return `${GH_API_BASE}/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${encodePath(
    filePath
  )}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;
}

function repoPutUrl(filePath) {
  return `${GH_API_BASE}/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${encodePath(filePath)}`;
}

function rawUrl(filePath) {
  return `https://raw.githubusercontent.com/${GITHUB_USERNAME}/${GITHUB_REPO}/${GITHUB_BRANCH}/${filePath}`;
}

function toBase64Utf8(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

function fromBase64Utf8(b64) {
  return Buffer.from(b64, "base64").toString("utf8");
}

function normalizeProduct(p) {
  const obj = p && typeof p === "object" ? p : {};
  const id = obj.id ?? (Date.now().toString() + "-" + crypto.randomBytes(3).toString("hex"));
  return {
    id,
    name: String(obj.name || "").trim(),
    description: String(obj.description || "").trim(),
    category: String(obj.category || "").trim(),
    gender: String(obj.gender || "").trim(),
    price: Number(obj.price) || 0,
    image: String(obj.image || "").trim(), // dataURL or URL
    createdAt: obj.createdAt || new Date().toISOString(),
  };
}

function validateProductBase(p) {
  if (!p.name) return "Product name is required";
  if (!p.category) return "Category is required";
  if (!p.gender) return "Gender is required";
  if (typeof p.price !== "number" || Number.isNaN(p.price)) return "Price must be a number";
  if (!p.image) return "Image is required";
  return null;
}

function parseDataUrl(dataUrl) {
  const m = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(dataUrl || "");
  if (!m) return null;
  return { mime: m[1], b64: m[2] };
}

function extFromMime(mime) {
  if (mime === "image/jpeg") return "jpg";
  if (mime === "image/png") return "png";
  if (mime === "image/webp") return "webp";
  if (mime === "image/gif") return "gif";
  return "png";
}

// ---- GitHub: products.json ----
async function getProductsFileFromGitHub() {
  const res = await fetch(contentUrl(PRODUCTS_FILE), { headers: ghHeaders() });

  if (res.status === 404) return { sha: null, products: [] };

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`GitHub GET products failed: ${res.status} ${txt}`);
  }

  const data = await res.json();
  const decoded = fromBase64Utf8(data.content || "");

  let products = [];
  try {
    const parsed = JSON.parse(decoded);
    products = Array.isArray(parsed) ? parsed : [];
  } catch {
    products = [];
  }

  return { sha: data.sha, products };
}

async function putProductsFileToGitHub(products, sha) {
  const res = await fetch(repoPutUrl(PRODUCTS_FILE), {
    method: "PUT",
    headers: { ...ghHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      message: `Update ${PRODUCTS_FILE} - ${new Date().toISOString()}`,
      content: toBase64Utf8(JSON.stringify(products, null, 2)),
      branch: GITHUB_BRANCH,
      ...(sha ? { sha } : {}),
    }),
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`GitHub PUT products failed: ${res.status} ${txt}`);
  }

  return res.json();
}

// ---- GitHub: upload image ----
async function uploadImageToGitHub(dataUrl, productId) {
  if (dataUrl.startsWith("http")) return dataUrl;

  const parsed = parseDataUrl(dataUrl);
  if (!parsed) throw new Error("Invalid image format. Must be a base64 data URL.");

  const { mime, b64 } = parsed;
  const ext = extFromMime(mime);

  const filePath = `public/uploads/${productId}-${Date.now()}.${ext}`;

  // Rough size guard
  const approxBytes = Math.floor((b64.length * 3) / 4);
  if (approxBytes > 1_500_000) {
    throw new Error("Image too large. Please upload a smaller image (try under ~1MB).");
  }

  const res = await fetch(repoPutUrl(filePath), {
    method: "PUT",
    headers: { ...ghHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      message: `Upload image ${filePath}`,
      content: b64,
      branch: GITHUB_BRANCH,
    }),
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`GitHub PUT image failed: ${res.status} ${txt}`);
  }

  return rawUrl(filePath);
}

// ---- API ----
app.get("/api/products", async (req, res) => {
  try {
    const { products } = await getProductsFileFromGitHub();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: "Failed to load products", details: String(err.message || err) });
  }
});

app.post("/api/products", requireAdmin, async (req, res) => {
  try {
    const raw = (req.body && (req.body.product || req.body)) || {};
    const product = normalizeProduct(raw);

    const msg = validateProductBase(product);
    if (msg) return res.status(400).json({ error: msg });

    // Upload image first → replace with URL
    product.image = await uploadImageToGitHub(product.image, product.id);

    const { sha, products: existing } = await getProductsFileFromGitHub();
    const list = Array.isArray(existing) ? existing : [];
    const updated = [product, ...list];

    await putProductsFileToGitHub(updated, sha);

    res.json({ ok: true, product, count: updated.length });
  } catch (err) {
    // ✅ return full detail to frontend
    res.status(500).json({ error: "Failed to add product", details: String(err.message || err) });
  }
});

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const { sha, products: existing } = await getProductsFileFromGitHub();
    const list = Array.isArray(existing) ? existing : [];

    const updated = list.filter((p) => String(p.id) !== id);
    if (updated.length === list.length) return res.status(404).json({ error: "Product not found" });

    await putProductsFileToGitHub(updated, sha);
    res.json({ ok: true, deletedId: id, count: updated.length });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete product", details: String(err.message || err) });
  }
});

app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
