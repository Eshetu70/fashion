/**
 * server.js (Node 18+)
 * - Serves frontend from /public
 * - API reads/writes products.json in GitHub repo securely
 * - Accepts multipart/form-data for product upload (image file)
 *
 * Routes:
 *   GET  /                  -> public/index.html
 *   GET  /health            -> ok
 *   GET  /api/products      -> list products
 *   POST /api/products      -> add product (admin, multipart)
 *   DELETE /api/products/:id-> delete product (admin)
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");

if (typeof fetch !== "function") {
  throw new Error("Global fetch missing. Use Node.js 18+");
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" })); // only for JSON routes, not file uploads

// ---------- Static frontend ----------
const publicDir = path.join(__dirname, "public");
const indexFile = path.join(publicDir, "index.html");
app.use(express.static(publicDir));

app.get("/", (req, res) => {
  if (fs.existsSync(indexFile)) return res.sendFile(indexFile);
  return res.status(200).send("Backend running, but /public/index.html missing.");
});

app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- ENV ----------
const PORT = process.env.PORT || 3000;

const {
  GITHUB_TOKEN,
  GITHUB_USERNAME,
  GITHUB_REPO,
  PRODUCTS_FILE = "products.json",
  GITHUB_BRANCH = "main",
  ADMIN_API_KEY,
  IMAGES_DIR = "images" // folder inside your repo
} = process.env;

if (!GITHUB_USERNAME || !GITHUB_REPO) console.warn("⚠️ Missing GITHUB_USERNAME or GITHUB_REPO");
if (!GITHUB_TOKEN) console.warn("⚠️ Missing GITHUB_TOKEN (writes will fail)");
if (!ADMIN_API_KEY) console.warn("⚠️ Missing ADMIN_API_KEY (writes blocked)");

const GH_API_BASE = "https://api.github.com";

// ---------- Multer for multipart ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB
  },
});

// ---------- Helpers ----------
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

function toBase64(buf) {
  return Buffer.from(buf).toString("base64");
}

function toBase64Utf8(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

function fromBase64Utf8(b64) {
  return Buffer.from(b64, "base64").toString("utf8");
}

function normalizeProduct(p) {
  const id = p.id ?? (Date.now().toString() + "-" + crypto.randomBytes(3).toString("hex"));
  return {
    id,
    name: String(p.name || "").trim(),
    description: String(p.description || "").trim(),
    category: String(p.category || "").trim(),
    gender: String(p.gender || "").trim(),
    price: Number(p.price) || 0,
    image: String(p.image || "").trim(),
    createdAt: p.createdAt || new Date().toISOString(),
  };
}

function validateProduct(p) {
  if (!p.name) return "Product name is required";
  if (!p.category) return "Category is required";
  if (!p.gender) return "Gender is required";
  if (typeof p.price !== "number" || Number.isNaN(p.price)) return "Price must be a number";
  if (!p.image) return "Image URL is required";
  return null;
}

function productsContentUrlWithRef() {
  return `${GH_API_BASE}/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${encodeURIComponent(
    PRODUCTS_FILE
  )}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;
}

function repoContentPutUrl(filePath) {
  // filePath like "images/abc.png" or "products.json"
  return `${GH_API_BASE}/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${encodeURIComponent(filePath)}`;
}

function rawUrlFor(filePath) {
  // raw GitHub URL for public access
  return `https://raw.githubusercontent.com/${GITHUB_USERNAME}/${GITHUB_REPO}/${GITHUB_BRANCH}/${filePath}`;
}

// ---------- GitHub read/write: products.json ----------
async function getProductsFileFromGitHub() {
  const res = await fetch(productsContentUrlWithRef(), { headers: ghHeaders() });

  if (res.status === 404) return { sha: null, products: [] };

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`GitHub GET failed: ${res.status} ${txt}`);
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
  const body = {
    message: `Update ${PRODUCTS_FILE} - ${new Date().toISOString()}`,
    content: toBase64Utf8(JSON.stringify(products, null, 2)),
    branch: GITHUB_BRANCH,
  };
  if (sha) body.sha = sha;

  const res = await fetch(repoContentPutUrl(PRODUCTS_FILE), {
    method: "PUT",
    headers: { ...ghHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`GitHub PUT products failed: ${res.status} ${txt}`);
  }

  return res.json();
}

// ---------- GitHub upload image ----------
async function uploadImageToGitHub(fileBuffer, originalName, mimeType) {
  const ext =
    (originalName && originalName.includes(".") && originalName.split(".").pop()) ||
    (mimeType && mimeType.includes("/") && mimeType.split("/")[1]) ||
    "png";

  const safeExt = String(ext).replace(/[^a-z0-9]/gi, "").toLowerCase() || "png";
  const fileName = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}.${safeExt}`;
  const filePath = `${IMAGES_DIR}/${fileName}`;

  // See if file already exists (rare) to get sha; otherwise create new
  let existingSha = null;
  const getRes = await fetch(
    `${GH_API_BASE}/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${encodeURIComponent(filePath)}?ref=${encodeURIComponent(GITHUB_BRANCH)}`,
    { headers: ghHeaders() }
  );

  if (getRes.ok) {
    const existing = await getRes.json();
    existingSha = existing.sha;
  }

  const body = {
    message: `Upload image ${fileName}`,
    content: toBase64(fileBuffer),
    branch: GITHUB_BRANCH,
  };
  if (existingSha) body.sha = existingSha;

  const putRes = await fetch(repoContentPutUrl(filePath), {
    method: "PUT",
    headers: { ...ghHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!putRes.ok) {
    const txt = await putRes.text();
    throw new Error(`GitHub PUT image failed: ${putRes.status} ${txt}`);
  }

  // Return raw URL to store in products.json
  return { filePath, url: rawUrlFor(filePath) };
}

// ---------- API ----------
app.get("/api/products", async (req, res) => {
  try {
    const { products } = await getProductsFileFromGitHub();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: "Failed to load products", details: String(err.message || err) });
  }
});

/**
 * POST /api/products (multipart/form-data)
 * Fields:
 *   name, description, category, gender, price
 * File:
 *   image (file)
 */
app.post("/api/products", requireAdmin, upload.single("image"), async (req, res) => {
  try {
    // multer parsed fields into req.body, file into req.file
    const file = req.file;
    if (!file) return res.status(400).json({ error: "Image file is required (field name: image)" });

    const name = (req.body?.name || "").trim();
    const description = (req.body?.description || "").trim();
    const category = (req.body?.category || "").trim();
    const gender = (req.body?.gender || "").trim();
    const price = Number(req.body?.price);

    // Upload image to GitHub and get URL
    const uploaded = await uploadImageToGitHub(file.buffer, file.originalname, file.mimetype);

    const { sha, products: existing } = await getProductsFileFromGitHub();

    const incoming = normalizeProduct({
      name,
      description,
      category,
      gender,
      price,
      image: uploaded.url, // store URL, not base64
    });

    const msg = validateProduct(incoming);
    if (msg) return res.status(400).json({ error: msg });

    const updated = [incoming, ...existing];
    await putProductsFileToGitHub(updated, sha);

    res.json({ ok: true, product: incoming, count: updated.length });
  } catch (err) {
    res.status(500).json({ error: "Failed to add product", details: String(err.message || err) });
  }
});

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const { sha, products: existing } = await getProductsFileFromGitHub();

    const updated = existing.filter((p) => String(p.id) !== id);
    if (updated.length === existing.length) return res.status(404).json({ error: "Product not found" });

    await putProductsFileToGitHub(updated, sha);
    res.json({ ok: true, deletedId: id, count: updated.length });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete product", details: String(err.message || err) });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`✅ Backend running: http://localhost:${PORT}`);
  console.log(`✅ Serving /public: ${publicDir}`);
});
