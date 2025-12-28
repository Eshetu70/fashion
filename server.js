/**
 * server.js (Node 18+)
 * - Serves frontend from /public
 * - API reads/writes products.json in GitHub repo securely (token stays server-side)
 *
 * Routes:
 *   GET  /                  -> public/index.html
 *   GET  /health            -> ok
 *   GET  /api/products      -> list products
 *   POST /api/products      -> add product (admin)
 *   PUT  /api/products/:id  -> update product (admin)
 *   DELETE /api/products/:id-> delete product (admin)
 *
 * Admin header:
 *   x-admin-key: <ADMIN_API_KEY>
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

if (typeof fetch !== "function") {
  throw new Error("Global fetch missing. Use Node.js 18+");
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "25mb" }));

// ---------- Static frontend ----------
const publicDir = path.join(__dirname, "public");
const indexFile = path.join(publicDir, "index.html");

console.log("PUBLIC DIR:", publicDir);
console.log("INDEX FILE:", indexFile);
console.log("INDEX EXISTS:", fs.existsSync(indexFile));

app.use(express.static(publicDir));

app.get("/", (req, res) => {
  res.sendFile(indexFile);
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/debug", (req, res) => {
  res.json({
    cwd: process.cwd(),
    __dirname,
    publicDir,
    indexFile,
    indexExists: fs.existsSync(indexFile),
  });
});

// ---------- ENV ----------
const PORT = process.env.PORT || 3000;

const {
  GITHUB_TOKEN,
  GITHUB_USERNAME,
  GITHUB_REPO,
  PRODUCTS_FILE = "products.json",
  GITHUB_BRANCH = "main",
  ADMIN_API_KEY,
} = process.env;

if (!GITHUB_USERNAME || !GITHUB_REPO) console.warn("⚠️ Missing GITHUB_USERNAME or GITHUB_REPO");
if (!GITHUB_TOKEN) console.warn("⚠️ Missing GITHUB_TOKEN (writes will fail)");
if (!ADMIN_API_KEY) console.warn("⚠️ Missing ADMIN_API_KEY (writes blocked)");

const GH_API_BASE = "https://api.github.com";

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

function contentUrlWithRef() {
  return `${GH_API_BASE}/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${encodeURIComponent(
    PRODUCTS_FILE
  )}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;
}

function toBase64Utf8(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

function fromBase64Utf8(b64) {
  return Buffer.from(b64, "base64").toString("utf8");
}

function normalizeProduct(p) {
  const id =
    p.id ??
    (Date.now().toString() + "-" + crypto.randomBytes(3).toString("hex"));

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
  if (!p.image) return "Image is required";
  return null;
}

// ---------- GitHub read/write ----------
async function getProductsFileFromGitHub() {
  const res = await fetch(contentUrlWithRef(), { headers: ghHeaders() });

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
  const url = `${GH_API_BASE}/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${encodeURIComponent(
    PRODUCTS_FILE
  )}`;

  const body = {
    message: `Update ${PRODUCTS_FILE} - ${new Date().toISOString()}`,
    content: toBase64Utf8(JSON.stringify(products, null, 2)),
    branch: GITHUB_BRANCH,
  };
  if (sha) body.sha = sha;

  const res = await fetch(url, {
    method: "PUT",
    headers: { ...ghHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`GitHub PUT failed: ${res.status} ${txt}`);
  }

  return res.json();
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

app.post("/api/products", requireAdmin, async (req, res) => {
  try {
    const { sha, products: existing } = await getProductsFileFromGitHub();

    const incoming = normalizeProduct(req.body?.product || req.body);
    const msg = validateProduct(incoming);
    if (msg) return res.status(400).json({ error: msg });

    const updated = [incoming, ...existing];
    await putProductsFileToGitHub(updated, sha);

    res.json({ ok: true, product: incoming, count: updated.length });
  } catch (err) {
    res.status(500).json({ error: "Failed to add product", details: String(err.message || err) });
  }
});

app.put("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const { sha, products: existing } = await getProductsFileFromGitHub();

    const idx = existing.findIndex((p) => String(p.id) === id);
    if (idx === -1) return res.status(404).json({ error: "Product not found" });

    const current = existing[idx];
    const patch = req.body?.product || req.body;

    const updatedProduct = normalizeProduct({
      ...current,
      ...patch,
      id: current.id,
      createdAt: current.createdAt,
    });

    const msg = validateProduct(updatedProduct);
    if (msg) return res.status(400).json({ error: msg });

    existing[idx] = updatedProduct;
    await putProductsFileToGitHub(existing, sha);

    res.json({ ok: true, product: updatedProduct });
  } catch (err) {
    res.status(500).json({ error: "Failed to update product", details: String(err.message || err) });
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
  console.log(`✅ Frontend:       http://localhost:${PORT}/`);
  console.log(`✅ API:            http://localhost:${PORT}/api/products`);
  console.log(`✅ Debug:          http://localhost:${PORT}/debug`);
});
