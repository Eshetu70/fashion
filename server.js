require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();

// ✅ CORS
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "x-admin-key"],
}));
app.options(/.*/, cors());

// JSON for non-multipart endpoints
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const { MONGODB_URI, ADMIN_API_KEY, EMAIL_FROM, EMAIL_TO, GMAIL_APP_PASSWORD } = process.env;

if (!MONGODB_URI) console.error("❌ Missing MONGODB_URI in env");
if (!ADMIN_API_KEY) console.error("❌ Missing ADMIN_API_KEY in env");

// -------------------
// MongoDB Connect
// -------------------
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

// -------------------
// Multer (memory)
// -------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
});

// -------------------
// Admin Auth
// -------------------
function requireAdmin(req, res, next) {
  const key = req.header("x-admin-key");
  if (!ADMIN_API_KEY) return res.status(500).json({ error: "Server missing ADMIN_API_KEY" });
  if (!key || key !== ADMIN_API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// -------------------
// Helpers
// -------------------
function extFromMime(mime) {
  if (mime === "image/jpeg") return "jpeg";
  if (mime === "image/png") return "png";
  if (mime === "image/webp") return "webp";
  if (mime === "image/gif") return "gif";
  return "png";
}

function makeId() {
  return Date.now().toString() + "-" + crypto.randomBytes(3).toString("hex");
}

function validateFields(body) {
  if (!body.name) return "Product name is required";
  if (!body.category) return "Category is required";
  if (!body.gender) return "Gender is required";
  const price = Number(body.price);
  if (Number.isNaN(price)) return "Price must be a number";
  return null;
}

function money(n) {
  return (Number(n) || 0).toFixed(0);
}

function escape(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// -------------------
// Email Sender
// -------------------
function buildTransporter() {
  if (!EMAIL_FROM || !GMAIL_APP_PASSWORD) return null;

  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: EMAIL_FROM,
      pass: GMAIL_APP_PASSWORD,
    },
  });
}

async function sendOrderEmail(order) {
  const transporter = buildTransporter();
  if (!transporter) {
    console.log("📧 Email not configured. Missing EMAIL_FROM or GMAIL_APP_PASSWORD.");
    return;
  }

  const to = EMAIL_TO || EMAIL_FROM;

  const itemsHtml = (order.items || [])
    .map(
      (i) => `
      <tr>
        <td style="padding:8px;border-bottom:1px solid #eee;">${escape(i.name)}</td>
        <td style="padding:8px;border-bottom:1px solid #eee; text-align:center;">${i.qty}</td>
        <td style="padding:8px;border-bottom:1px solid #eee; text-align:right;">${money(i.price)} ETB</td>
        <td style="padding:8px;border-bottom:1px solid #eee; text-align:right;">${money(i.subtotal)} ETB</td>
      </tr>`
    )
    .join("");

  const telebirrSection =
    order.payment?.method === "telebirr"
      ? `
        <p><b>Telebirr Txn ID:</b> ${escape(order.payment.telebirrTxnId || "")}</p>
        <p><b>Proof Uploaded:</b> ${order.payment.proofImage ? "YES" : "NO"}</p>
      `
      : "";

  const subject = `🧾 New Order: ${order.orderId} | Total ${money(order.total)} ETB`;

  const html = `
    <div style="font-family:Arial,sans-serif; line-height:1.5;">
      <h2>New Order Received ✅</h2>
      <p><b>Order ID:</b> ${escape(order.orderId)}</p>
      <p><b>Date:</b> ${new Date(order.createdAt).toLocaleString()}</p>

      <hr/>

      <h3>Customer Info</h3>
      <p><b>Name:</b> ${escape(order.customer.fullName)}</p>
      <p><b>Phone:</b> ${escape(order.customer.phone)}</p>
      <p><b>Email:</b> ${escape(order.customer.email || "")}</p>
      <p><b>Address:</b> ${escape(order.customer.address)}</p>

      <hr/>

      <h3>Items</h3>
      <table style="width:100%; border-collapse:collapse;">
        <thead>
          <tr>
            <th style="text-align:left; padding:8px; border-bottom:2px solid #ddd;">Item</th>
            <th style="text-align:center; padding:8px; border-bottom:2px solid #ddd;">Qty</th>
            <th style="text-align:right; padding:8px; border-bottom:2px solid #ddd;">Price</th>
            <th style="text-align:right; padding:8px; border-bottom:2px solid #ddd;">Subtotal</th>
          </tr>
        </thead>
        <tbody>${itemsHtml}</tbody>
      </table>

      <p style="text-align:right;"><b>Total:</b> ${money(order.total)} ETB</p>

      <hr/>

      <h3>Payment</h3>
      <p><b>Method:</b> ${escape(order.payment.method)}</p>
      <p><b>Status:</b> ${escape(order.payment.status)}</p>
      ${telebirrSection}
    </div>
  `;

  await transporter.sendMail({ from: EMAIL_FROM, to, subject, html });
  console.log("📧 Order email sent to:", to);
}

// -------------------
// MongoDB Schemas
// -------------------
const productSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    description: { type: String, default: "" },
    category: { type: String, required: true },
    gender: { type: String, required: true },
    price: { type: Number, required: true },
    image: { type: String, required: true }, // base64 data URL
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "fashion" }
);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, required: true, unique: true },
    items: { type: Array, default: [] },
    total: { type: Number, required: true },
    customer: {
      fullName: String,
      phone: String,
      email: String,
      address: String,
      note: String,
    },
    payment: {
      method: String, // cash | card | telebirr
      status: String, // pending | submitted
      telebirrTxnId: String,
      proofImage: String, // base64 dataURL if uploaded
    },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "orders" }
);

const Product = mongoose.model("Product", productSchema);
const Order = mongoose.model("Order", orderSchema);

// -------------------
// Routes
// -------------------
app.get("/", (req, res) => res.send("✅ Fashion backend running"));
app.get("/health", (req, res) => res.json({ ok: true }));

// Products
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find({}).sort({ createdAt: -1 }).lean();
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: "Failed to load products", details: err.message });
  }
});

app.post("/api/products", requireAdmin, upload.single("image"), async (req, res) => {
  try {
    const msg = validateFields(req.body);
    if (msg) return res.status(400).json({ error: msg });
    if (!req.file) return res.status(400).json({ error: "Image file is required" });

    const mime = req.file.mimetype || "image/png";
    const ext = extFromMime(mime);
    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:image/${ext};base64,${b64}`;

    const product = {
      id: makeId(),
      name: String(req.body.name).trim(),
      description: String(req.body.description || "").trim(),
      category: String(req.body.category).trim(),
      gender: String(req.body.gender).trim(),
      price: Number(req.body.price) || 0,
      image: dataUrl,
      createdAt: new Date(),
    };

    const saved = await Product.create(product);
    res.json({ ok: true, product: saved });
  } catch (err) {
    res.status(500).json({ error: "Failed to add product", details: err.message });
  }
});

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const deleted = await Product.findOneAndDelete({ id }).lean();
    if (!deleted) return res.status(404).json({ error: "Product not found" });
    res.json({ ok: true, deletedId: id });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete product", details: err.message });
  }
});

// ✅ Checkout orders
app.post("/api/orders/checkout", async (req, res) => {
  try {
    const payload = req.body || {};
    const items = Array.isArray(payload.items) ? payload.items : [];
    if (!items.length) return res.status(400).json({ error: "Cart is empty" });

    const total = Number(payload.total) || 0;
    if (total <= 0) return res.status(400).json({ error: "Invalid total" });

    const customer = payload.customer || {};
    if (!customer.fullName || !customer.phone || !customer.address) {
      return res.status(400).json({ error: "Customer name, phone, and address are required" });
    }

    const payment = payload.payment || {};
    if (!payment.method) return res.status(400).json({ error: "Payment method required" });

    // If telebirr method, require txn id + proof
    if (payment.method === "telebirr") {
      if (!payment.telebirrTxnId) return res.status(400).json({ error: "Telebirr transaction ID required" });
      if (!payment.proofImage) return res.status(400).json({ error: "Telebirr proof image required" });
    }

    const order = {
      orderId: "ORD-" + makeId(),
      items,
      total,
      customer: {
        fullName: String(customer.fullName || "").trim(),
        phone: String(customer.phone || "").trim(),
        email: String(customer.email || "").trim(),
        address: String(customer.address || "").trim(),
        note: String(customer.note || "").trim(),
      },
      payment: {
        method: String(payment.method || "").trim(),
        status: payment.method === "cash" ? "pending" : "submitted",
        telebirrTxnId: String(payment.telebirrTxnId || "").trim(),
        proofImage: String(payment.proofImage || ""), // base64
      },
      createdAt: new Date(),
    };

    const saved = await Order.create(order);

    // ✅ Send email to you
    sendOrderEmail(saved).catch((e) => console.error("Email send failed:", e.message));

    res.json({ ok: true, order: saved });
  } catch (err) {
    res.status(500).json({ error: "Checkout failed", details: err.message });
  }
});

// -------------------
// Start server
// -------------------
app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
