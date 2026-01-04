/**
 * server.js ✅ FULL UPDATED (Sena Fashion) — 2026-01-04 FIXED
 * Fixes:
 * ✅ JWT_SECRET newline / double-line issues on Render (sanitized)
 * ✅ Checkout spinning / slow response (email sent async, not blocking order)
 * ✅ Adds missing routes your frontend calls: /api/admin/ping, /api/admin/test-email
 * ✅ CORS allow GitHub Pages + local + Render
 * ✅ Uploads + absolute URL helpers
 *
 * npm i express cors mongoose multer bcryptjs jsonwebtoken nodemailer dotenv
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const mongoose = require("mongoose");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();
app.set("trust proxy", 1);

// ---------------- ENV ----------------
const {
  PORT = 3000,
  MONGODB_URI,
  ADMIN_API_KEY,

  JWT_SECRET: JWT_SECRET_RAW,

  // SMTP (recommended)
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,

  // Gmail fallback
  GMAIL_USER,
  GMAIL_APP_PASSWORD,

  EMAIL_FROM,
  EMAIL_FROM_NAME,
  OWNER_EMAIL,
  PUBLIC_BASE_URL,

  // Optional: set your GitHub pages origin explicitly
  GITHUB_PAGES_ORIGIN, // e.g. https://eshetu70.github.io
} = process.env;

// ✅ Hard-fix: Render paste/newline/space issues
const JWT_SECRET = String(JWT_SECRET_RAW || "")
  .replace(/\s+/g, "") // removes ALL whitespace: spaces/newlines/tabs
  .trim();

console.log("🔐 JWT_SECRET length:", JWT_SECRET.length);

if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI");
  process.exit(1);
}
if (!ADMIN_API_KEY) {
  console.error("❌ Missing ADMIN_API_KEY");
  process.exit(1);
}
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("❌ Missing/weak JWT_SECRET (must be ONE LINE, 32+ chars)");
  process.exit(1);
}

// ---------------- CORS (GitHub Pages + local + Render) ----------------
// You can add more origins here if needed.
const allowedOrigins = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "https://eshetu70.github.io", // your common GitHub pages
].filter(Boolean);

if (GITHUB_PAGES_ORIGIN) allowedOrigins.push(String(GITHUB_PAGES_ORIGIN).trim());

app.use(
  cors({
    origin: (origin, cb) => {
      // allow no-origin requests (Postman/server-to-server)
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked: " + origin));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
  })
);
app.options(/.*/, cors());

// Body parsers
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));

// ---------------- UPLOADS ----------------
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(
  "/uploads",
  express.static(UPLOAD_DIR, {
    maxAge: "7d",
    setHeaders: (res) => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
      res.setHeader("Cache-Control", "public, max-age=604800");
    },
  })
);

// ---------------- MONGO ----------------
mongoose
  .connect(MONGODB_URI, {
    // keeps Render stable
    serverSelectionTimeoutMS: 10000,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB error:", err.message);
    process.exit(1);
  });

// ---------------- MODELS ----------------
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true, unique: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, required: true, trim: true },
    gender: { type: String, required: true, trim: true },
    price: { type: Number, required: true },
    image: { type: String, default: "" }, // absolute URL
  },
  { timestamps: true }
);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, required: true, unique: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "FashionUser", required: true, index: true },
    items: [
      {
        productId: { type: String, required: true },
        name: { type: String, required: true },
        price: { type: Number, required: true },
        qty: { type: Number, required: true },
        image: { type: String, default: "" },
      },
    ],
    total: { type: Number, required: true },
    customer: {
      fullName: { type: String, required: true },
      phone: { type: String, required: true },
      email: { type: String, default: "" },
      address: { type: String, required: true },
      city: { type: String, default: "" },
      country: { type: String, default: "" },
      notes: { type: String, default: "" },
    },
    payment: {
      method: { type: String, enum: ["cash", "card", "telebirr"], required: true },
      status: { type: String, enum: ["pending", "paid", "failed"], default: "pending" },
      telebirrRef: { type: String, default: "" },
      proofUrl: { type: String, default: "" },
    },
    status: { type: String, enum: ["placed", "processing", "delivered", "cancelled"], default: "placed" },
  },
  { timestamps: true }
);

const User = mongoose.model("FashionUser", userSchema, "fashion_users");
const Product = mongoose.model("FashionProduct", productSchema, "fashion_products");
const Order = mongoose.model("FashionOrder", orderSchema, "fashion_orders");

// ---------------- HELPERS ----------------
function baseUrlFromReq(req) {
  if (PUBLIC_BASE_URL) return String(PUBLIC_BASE_URL).replace(/\/+$/, "");
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").toString().split(",")[0].trim();
  const host = req.get("host");
  return `${proto}://${host}`;
}
function toAbsoluteUrl(req, maybeUrlOrPath) {
  if (!maybeUrlOrPath) return "";
  const v = String(maybeUrlOrPath);
  if (v.startsWith("http://") || v.startsWith("https://")) return v;
  const base = baseUrlFromReq(req);
  if (v.startsWith("/")) return `${base}${v}`;
  return `${base}/${v}`;
}
function safeJsonParse(input, fallback) {
  try {
    if (typeof input === "string") return JSON.parse(input);
    return input ?? fallback;
  } catch {
    return fallback;
  }
}
function makeOrderId() {
  return `SF-${Date.now()}-${Math.random().toString(16).slice(2, 8).toUpperCase()}`;
}
function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function requireAdmin(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (!key || key !== ADMIN_API_KEY) return res.status(401).json({ error: "Unauthorized (admin key required)" });
  next();
}
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const decoded = jwt.verify(String(token).trim(), JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------------- MULTER ----------------
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase() || ".jpg";
    const safeExt = [".png", ".jpg", ".jpeg", ".webp"].includes(ext) ? ext : ".jpg";
    cb(null, `${Date.now()}-${Math.random().toString(16).slice(2)}${safeExt}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/jpg", "image/webp"].includes(file.mimetype);
    cb(ok ? null : new Error("Only image files allowed (png/jpg/webp)"), ok);
  },
});

// ---------------- EMAIL ----------------
function getMailFrom() {
  const fromEmail = EMAIL_FROM || SMTP_USER || GMAIL_USER || "no-reply@sena-fashion.com";
  const fromName = EMAIL_FROM_NAME || "Sena Fashion";
  return `"${fromName}" <${fromEmail}>`;
}

async function createTransporter() {
  if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
    const secure = String(SMTP_SECURE || "").toLowerCase() === "true";
    return nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
  }

  if (GMAIL_USER && GMAIL_APP_PASSWORD) {
    return nodemailer.createTransport({
      service: "gmail",
      auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
    });
  }

  return null;
}

function buildCustomerEmailHtml({ customerName, orderId, items, total, status, paymentStatus }) {
  const rows = (items || [])
    .map(
      (it) => `
      <tr>
        <td style="padding:10px;border-bottom:1px solid #eee;">${escapeHtml(it.name)}</td>
        <td style="padding:10px;border-bottom:1px solid #eee;text-align:center;">${Number(it.qty || 0)}</td>
        <td style="padding:10px;border-bottom:1px solid #eee;text-align:right;">ETB ${Number(it.price || 0).toFixed(0)}</td>
      </tr>
    `
    )
    .join("");

  return `
  <div style="font-family:Arial,Helvetica,sans-serif;line-height:1.5;color:#111;">
    <div style="max-width:650px;margin:0 auto;padding:18px;border:1px solid #eee;border-radius:12px;">
      <h2 style="margin:0 0 6px;">Sena Fashion — Order Update</h2>
      <p style="margin:0 0 14px;color:#444;">Hi ${escapeHtml(customerName || "Customer")},</p>

      <div style="background:#f7f7fb;border:1px solid #ececf3;border-radius:10px;padding:12px;margin:10px 0 16px;">
        <div><b>Order ID:</b> ${escapeHtml(orderId)}</div>
        <div><b>Order Status:</b> ${escapeHtml(status)}</div>
        <div><b>Payment Status:</b> ${escapeHtml(paymentStatus)}</div>
      </div>

      <h3 style="margin:0 0 8px;">Order Summary</h3>
      <table style="width:100%;border-collapse:collapse;border:1px solid #eee;border-radius:10px;overflow:hidden;">
        <thead>
          <tr style="background:#111;color:#fff;">
            <th style="padding:10px;text-align:left;">Item</th>
            <th style="padding:10px;text-align:center;">Qty</th>
            <th style="padding:10px;text-align:right;">Price</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
        <tfoot>
          <tr>
            <td colspan="2" style="padding:12px;text-align:right;border-top:1px solid #eee;"><b>Total</b></td>
            <td style="padding:12px;text-align:right;border-top:1px solid #eee;"><b>ETB ${Number(total || 0).toFixed(0)}</b></td>
          </tr>
        </tfoot>
      </table>

      <p style="margin:16px 0 0;color:#444;">
        If you have any questions, reply to this email and we will help you.
      </p>

      <p style="margin:14px 0 0;color:#777;font-size:13px;">
        Thank you for shopping with <b>Sena Fashion</b>.
      </p>
    </div>
  </div>`;
}

async function sendCustomerEmail({ to, subject, html, text }) {
  const transporter = await createTransporter();
  if (!transporter) {
    return { ok: false, skipped: true, message: "Email not configured (missing SMTP or Gmail env vars)." };
  }
  const mail = {
    from: getMailFrom(),
    to,
    subject,
    text: text || "Sena Fashion — Order update",
    html,
    replyTo: OWNER_EMAIL || undefined,
  };
  await transporter.sendMail(mail);
  return { ok: true };
}

// ✅ Critical fix: email should never block API response
function sendEmailInBackground(fn) {
  setImmediate(async () => {
    try {
      await fn();
    } catch (e) {
      console.warn("⚠️ Background email failed:", e.message);
    }
  });
}

// ---------------- ROUTES ----------------
app.get("/", (req, res) => {
  res.json({ ok: true, app: "Sena Fashion API", time: new Date().toISOString() });
});

// ✅ Used by your frontend "Test Admin"
app.get("/api/admin/ping", requireAdmin, (req, res) => {
  res.json({ ok: true, admin: true, time: new Date().toISOString() });
});

// ✅ Used by your frontend "Test Email"
app.get("/api/admin/test-email", requireAdmin, async (req, res) => {
  try {
    if (!OWNER_EMAIL) return res.status(400).json({ error: "OWNER_EMAIL not set in env" });

    const html = buildCustomerEmailHtml({
      customerName: "Owner",
      orderId: "SF-TEST-EMAIL",
      items: [{ name: "Test Item", qty: 1, price: 1000 }],
      total: 1000,
      status: "placed",
      paymentStatus: "pending",
    });

    const result = await sendCustomerEmail({
      to: OWNER_EMAIL,
      subject: "Sena Fashion — Test Email",
      html,
      text: "Test email from Sena Fashion backend.",
    });

    if (!result.ok && result.skipped) return res.status(400).json(result);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ error: "Test email failed", details: e.message });
  }
});

// ---------- AUTH ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};
    if (!fullName || !email || !password) return res.status(400).json({ error: "fullName, email, password required" });

    const cleanEmail = String(email).trim().toLowerCase();
    const exists = await User.findOne({ email: cleanEmail }).lean();
    if (exists) return res.status(409).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({ fullName: String(fullName).trim(), email: cleanEmail, passwordHash });

    const token = jwt.sign({ userId: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: "30d" });

    res.json({ ok: true, token, user: { id: String(user._id), fullName: user.fullName, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: "Register failed", details: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password required" });

    const cleanEmail = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: cleanEmail });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ ok: true, token, user: { id: String(user._id), fullName: user.fullName, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: "Login failed", details: e.message });
  }
});

// ---------- PRODUCTS (Public) ----------
app.get("/api/products", async (req, res) => {
  try {
    const { category, gender, q } = req.query || {};
    const filter = {};
    if (category) filter.category = String(category).toLowerCase();
    if (gender) filter.gender = String(gender).toLowerCase();

    if (q) {
      const rx = new RegExp(String(q).trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      filter.$or = [{ name: rx }, { description: rx }, { category: rx }, { gender: rx }];
    }

    const products = await Product.find(filter).sort({ createdAt: -1 }).lean();
    res.json({ ok: true, products });
  } catch (e) {
    res.status(500).json({ error: "Failed to load products", details: e.message });
  }
});

// ---------- PRODUCTS (Admin CRUD) ----------
app.post("/api/products", requireAdmin, upload.single("image"), async (req, res) => {
  try {
    const body = req.body || {};
    const name = body.name;
    const description = body.description || "";
    const category = body.category;
    const gender = body.gender;
    const price = Number(body.price);

    if (!name || !category || !gender || Number.isNaN(price)) {
      return res.status(400).json({ error: "name, category, gender, price required" });
    }

    let image = body.image || "";
    if (req.file) image = toAbsoluteUrl(req, `/uploads/${req.file.filename}`);
    else if (image) image = toAbsoluteUrl(req, image);

    const doc = await Product.create({
      name: String(name).trim(),
      description: String(description || ""),
      category: String(category).trim().toLowerCase(),
      gender: String(gender).trim().toLowerCase(),
      price,
      image,
    });

    res.json({ ok: true, product: doc });
  } catch (e) {
    res.status(500).json({ error: "Failed to add product", details: e.message });
  }
});

app.put("/api/products/:id", requireAdmin, upload.single("image"), async (req, res) => {
  try {
    const id = req.params.id;
    const body = req.body || {};

    const patch = {};
    if (body.name != null) patch.name = String(body.name).trim();
    if (body.description != null) patch.description = String(body.description || "");
    if (body.category != null) patch.category = String(body.category).trim().toLowerCase();
    if (body.gender != null) patch.gender = String(body.gender).trim().toLowerCase();
    if (body.price != null) patch.price = Number(body.price);

    if (req.file) patch.image = toAbsoluteUrl(req, `/uploads/${req.file.filename}`);
    else if (body.image != null) patch.image = toAbsoluteUrl(req, String(body.image || ""));

    const updated = await Product.findByIdAndUpdate(id, patch, { new: true }).lean();
    if (!updated) return res.status(404).json({ error: "Product not found" });

    res.json({ ok: true, product: updated });
  } catch (e) {
    res.status(500).json({ error: "Failed to update product", details: e.message });
  }
});

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const deleted = await Product.findByIdAndDelete(id).lean();
    if (!deleted) return res.status(404).json({ error: "Product not found" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Failed to delete product", details: e.message });
  }
});

// ---------- ORDERS (Customer places order) ----------
app.post("/api/orders", requireAuth, upload.single("proof"), async (req, res) => {
  try {
    const userId = req.user.userId;

    const rawItems = req.body.items ?? req.body.cartItems ?? req.body.cart ?? null;
    const items = safeJsonParse(rawItems, Array.isArray(rawItems) ? rawItems : []);

    if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "Cart items required" });

    const customer = safeJsonParse(req.body.customer, null) || {
      fullName: req.body.fullName || req.body.customerName || "",
      phone: req.body.phone || "",
      email: req.body.email || "",
      address: req.body.address || "",
      city: req.body.city || "",
      country: req.body.country || "",
      notes: req.body.notes || "",
    };

    if (!customer.fullName || !customer.phone || !customer.address) {
      return res.status(400).json({ error: "Customer fullName, phone, address required" });
    }

    const payment = safeJsonParse(req.body.payment, null) || {
      method: req.body.paymentMethod || "cash",
      status: req.body.paymentStatus || "pending",
      telebirrRef: req.body.telebirrRef || "",
      proofUrl: req.body.proofUrl || "",
    };

    if (!["cash", "card", "telebirr"].includes(payment.method)) return res.status(400).json({ error: "Invalid payment.method" });
    if (!["pending", "paid", "failed"].includes(payment.status)) payment.status = "pending";

    if (req.file) payment.proofUrl = toAbsoluteUrl(req, `/uploads/${req.file.filename}`);
    else if (payment.proofUrl) payment.proofUrl = toAbsoluteUrl(req, payment.proofUrl);

    const cleanItems = items.map((it) => ({
      productId: String(it.productId || it.id || it._id || ""),
      name: String(it.name || ""),
      price: Number(it.price || 0),
      qty: Number(it.qty || it.quantity || 1),
      image: toAbsoluteUrl(req, it.image || ""),
    }));

    const bad = cleanItems.find((x) => !x.productId || !x.name || Number.isNaN(x.price) || Number.isNaN(x.qty));
    if (bad) return res.status(400).json({ error: "Invalid item in cart" });

    const total =
      req.body.total != null
        ? Number(req.body.total)
        : cleanItems.reduce((sum, it) => sum + Number(it.price) * Number(it.qty), 0);

    if (Number.isNaN(total)) return res.status(400).json({ error: "Invalid total" });

    const orderId = makeOrderId();

    const order = await Order.create({
      orderId,
      userId,
      items: cleanItems,
      total,
      customer: {
        fullName: String(customer.fullName).trim(),
        phone: String(customer.phone).trim(),
        email: String(customer.email || "").trim(),
        address: String(customer.address).trim(),
        city: String(customer.city || "").trim(),
        country: String(customer.country || "").trim(),
        notes: String(customer.notes || "").trim(),
      },
      payment: {
        method: payment.method,
        status: payment.status,
        telebirrRef: String(payment.telebirrRef || ""),
        proofUrl: String(payment.proofUrl || ""),
      },
      status: "placed",
    });

    // ✅ Respond immediately (no waiting on email)
    res.json({ ok: true, order: { orderId: order.orderId, total: order.total, status: order.status, createdAt: order.createdAt } });

    // ✅ Email owner in background (never blocks checkout)
    if (OWNER_EMAIL) {
      sendEmailInBackground(async () => {
        const html = buildCustomerEmailHtml({
          customerName: "Owner",
          orderId: order.orderId,
          items: order.items,
          total: order.total,
          status: order.status,
          paymentStatus: order.payment.status,
        });
        await sendCustomerEmail({
          to: OWNER_EMAIL,
          subject: `New Order ${order.orderId} — Sena Fashion`,
          html,
          text: `New order ${order.orderId} total ETB ${order.total}`,
        });
      });
    }
  } catch (e) {
    res.status(500).json({ error: "Failed to place order", details: e.message });
  }
});

// ---------- CUSTOMER: MY ORDERS ----------
app.get("/api/orders/my", requireAuth, async (req, res) => {
  try {
    const userId = req.user.userId;
    const orders = await Order.find({ userId }).sort({ createdAt: -1 }).lean();
    res.json({ ok: true, orders });
  } catch (e) {
    res.status(500).json({ error: "Failed to load orders", details: e.message });
  }
});

// ---------- ADMIN: ALL ORDERS ----------
app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find({}).sort({ createdAt: -1 }).lean();
    res.json({ ok: true, orders });
  } catch (e) {
    res.status(500).json({ error: "Failed to load admin orders", details: e.message });
  }
});

// ---------- ADMIN: UPDATE STATUS / PAYMENT ----------
app.put("/api/admin/orders/:orderId", requireAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status, paymentStatus, telebirrRef, proofUrl } = req.body || {};

    const patch = {};
    if (status && ["placed", "processing", "delivered", "cancelled"].includes(status)) patch.status = status;
    if (paymentStatus && ["pending", "paid", "failed"].includes(paymentStatus)) patch["payment.status"] = paymentStatus;
    if (telebirrRef != null) patch["payment.telebirrRef"] = String(telebirrRef || "");
    if (proofUrl != null) patch["payment.proofUrl"] = String(proofUrl || "");

    const updated = await Order.findOneAndUpdate({ orderId }, patch, { new: true }).lean();
    if (!updated) return res.status(404).json({ error: "Order not found" });

    res.json({ ok: true, order: updated });
  } catch (e) {
    res.status(500).json({ error: "Failed to update order", details: e.message });
  }
});

// ---------- ADMIN: EMAIL CUSTOMER ----------
app.post("/api/admin/orders/:orderId/email", requireAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { subject, message } = req.body || {};

    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ error: "Order not found" });

    const to = String(order.customer?.email || "").trim();
    if (!to) return res.status(400).json({ error: "Customer email not found for this order" });

    const niceSubject = subject && String(subject).trim() ? String(subject).trim() : `Your Order ${order.orderId} — Update`;
    const extraMsg = message && String(message).trim() ? String(message).trim() : "";

    const html = `
      ${buildCustomerEmailHtml({
        customerName: order.customer?.fullName,
        orderId: order.orderId,
        items: order.items,
        total: order.total,
        status: order.status,
        paymentStatus: order.payment?.status,
      })}
      ${
        extraMsg
          ? `<div style="max-width:650px;margin:12px auto 0;padding:0 18px;">
              <div style="border:1px solid #eee;border-radius:12px;padding:12px;font-family:Arial,Helvetica,sans-serif;color:#111;">
                <b>Message from Sena Fashion:</b>
                <div style="margin-top:8px;color:#333;white-space:pre-wrap;">${escapeHtml(extraMsg)}</div>
              </div>
            </div>`
          : ""
      }
    `;

    const result = await sendCustomerEmail({
      to,
      subject: niceSubject,
      html,
      text: `Order ${order.orderId} status: ${order.status}, payment: ${order.payment?.status}. ${extraMsg}`,
    });

    if (!result.ok && result.skipped) return res.status(400).json(result);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ error: "Failed to email customer", details: e.message });
  }
});

// ---------------- START ----------------
app.listen(Number(PORT), () => {
  console.log(`✅ Sena Fashion backend running on port ${PORT}`);
});
