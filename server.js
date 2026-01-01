/**
 * server.js ✅ FULL UPDATED (Sena Fashion) — FAST + MOBILE SAFE
 * - MongoDB (products, users, orders)
 * - Products CRUD (Admin key)
 * - Auth (register/login) JWT
 * - Orders (FormData OR JSON)
 * - Customer: My Orders
 * - Admin: View ALL orders, Update Status/Payment, Email customer
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

// ---------------- CORS ----------------
const corsOptions = {
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
};
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

// Body parsers
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ---------------- ENV ----------------
const {
  PORT = 3000,
  MONGODB_URI,
  ADMIN_API_KEY,
  JWT_SECRET,

  GMAIL_USER,
  GMAIL_APP_PASSWORD,
  EMAIL_FROM,
  EMAIL_FROM_NAME,
  OWNER_EMAIL,
  PUBLIC_BASE_URL,
} = process.env;

if (!MONGODB_URI) { console.error("❌ Missing MONGODB_URI"); process.exit(1); }
if (!ADMIN_API_KEY) { console.error("❌ Missing ADMIN_API_KEY"); process.exit(1); }
if (!JWT_SECRET) { console.error("❌ Missing JWT_SECRET"); process.exit(1); }

// ---------------- UPLOADS ----------------
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ✅ Serve uploads w/ caching (faster mobile)
app.use("/uploads", express.static(UPLOAD_DIR, {
  setHeaders(res){
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  }
}));

// ---------------- MONGO ----------------
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => { console.error("❌ MongoDB error:", err.message); process.exit(1); });

// ---------------- MODELS ----------------
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true, unique: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);
const User = mongoose.model("fashion_users", userSchema);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, required: true, trim: true },
    gender: { type: String, required: true, trim: true },
    price: { type: Number, required: true },
    image: { type: String, default: "" }, // store full URL
  },
  { timestamps: true }
);
const Product = mongoose.model("fashion_products", productSchema);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "fashion_users", required: true },
    items: [
      {
        productId: { type: String, required: true },
        name: { type: String, required: true },
        price: { type: Number, required: true },
        qty: { type: Number, required: true },
        image: { type: String, default: "" }, // store full URL
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
      proofUrl: { type: String, default: "" }, // full URL
    },
    status: { type: String, enum: ["placed", "processing", "delivered", "cancelled"], default: "placed" },
  },
  { timestamps: true }
);
const Order = mongoose.model("fashion_orders", orderSchema);

// ---------------- HELPERS ----------------
function publicBaseUrl(req) {
  return PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
}
function makeOrderId() {
  return "ORD-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 7).toUpperCase();
}
function safeTrim(v){ return String(v ?? "").trim(); }
function isDataUrl(v){ return typeof v === "string" && v.startsWith("data:"); }

// ---------------- MIDDLEWARE ----------------
function requireAdmin(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (!key || key !== ADMIN_API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const id = decoded.id || decoded.userId || decoded._id;
    if (!id) return res.status(401).json({ error: "Token missing user id" });
    req.user = { id: String(id) };
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------------- MULTER ----------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = (file.originalname || "file").replace(/[^\w.\-]+/g, "_");
    cb(null, Date.now() + "_" + safe);
  },
});
const uploadProductImage = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 } }).single("image");
const uploadOrderProof = multer({
  storage,
  limits: { fileSize: 3 * 1024 * 1024, fieldSize: 20 * 1024 * 1024, fields: 200 },
}).single("paymentProof");

// ---------------- EMAIL (GMAIL) ----------------
function getMailer() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) return null;
  return nodemailer.createTransport({
    service: "gmail",
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
  });
}

async function sendEmailSafe({ to, subject, text }) {
  const mailer = getMailer();
  if (!mailer) return { ok: false, reason: "Missing GMAIL_USER or GMAIL_APP_PASSWORD" };

  try {
    const fromEmail = EMAIL_FROM || GMAIL_USER;
    const fromName = EMAIL_FROM_NAME || "Sena Fashion";

    await mailer.sendMail({
      from: `${fromName} <${fromEmail}>`,
      to,
      subject,
      text,
    });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ✅ FAST: send email after response (no waiting)
function sendEmailAsync(payload){
  setImmediate(async () => {
    try{
      const r = await sendEmailSafe(payload);
      if(!r.ok) console.warn("⚠️ Email failed:", r.reason);
    }catch(e){
      console.warn("⚠️ Email error:", e.message);
    }
  });
}

function buildCustomerEmailText(order, customNote) {
  const items = (order.items || [])
    .map(i => `• ${i.name} x${i.qty} — ${i.price} ETB`)
    .join("\n");

  const note = (customNote || "").trim();
  const brand = EMAIL_FROM_NAME || "Sena Fashion";

  return `
Hello ${order.customer?.fullName || "Customer"},

Thank you for shopping with ${brand}.

${note ? note + "\n\n" : ""}Order Details:
- Order ID: ${order.orderId}
- Order Status: ${order.status}
- Payment Method: ${order.payment?.method || "-"}
- Payment Status: ${order.payment?.status || "-"}
- Total: ${order.total} ETB

Items:
${items || "-"}

If you have any questions, reply to this email and we will assist you.

Warm regards,
${brand} Support Team
  `.trim();
}

// ---------------- ROUTES ----------------
app.get("/", (req, res) => res.json({ ok: true, app: "Sena Fashion API" }));
app.get("/api/version", (req, res) => res.json({ version: "2026-01-01-full-pro-ui-fast-orders" }));

app.get("/api/admin/ping", requireAdmin, (req, res) => res.json({ ok: true }));

// ---------- AUTH ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};
    if (!fullName || !email || !password) return res.status(400).json({ error: "fullName, email, password required" });
    if (String(password).length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    const existing = await User.findOne({ email: String(email).toLowerCase() });
    if (existing) return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({
      fullName: String(fullName).trim(),
      email: String(email).toLowerCase().trim(),
      passwordHash,
    });

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ token });
  } catch (e) {
    return res.status(500).json({ error: "Register failed", details: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password required" });

    const user = await User.findOne({ email: String(email).toLowerCase() });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ token });
  } catch (e) {
    return res.status(500).json({ error: "Login failed", details: e.message });
  }
});

// ---------- PRODUCTS ----------
app.get("/api/products", async (req, res) => {
  try {
    const list = await Product.find().sort({ createdAt: -1 }).lean();
    res.json(
      list.map((p) => ({
        id: p._id.toString(),
        name: p.name,
        description: p.description,
        category: p.category,
        gender: p.gender,
        price: p.price,
        image: p.image,
        createdAt: p.createdAt,
      }))
    );
  } catch (e) {
    res.status(500).json({ error: "Failed to load products", details: e.message });
  }
});

app.post("/api/products", requireAdmin, (req, res) => {
  uploadProductImage(req, res, async (err) => {
    try {
      if (err) return res.status(400).json({ error: "Upload error", details: err.message });
      if (!req.file) return res.status(400).json({ error: "Image file is required" });

      const { name, description = "", category, gender, price } = req.body || {};
      if (!name || !category || !gender || !price) return res.status(400).json({ error: "name, category, gender, price required" });

      const imgUrl = `${publicBaseUrl(req)}/uploads/${req.file.filename}`;

      const created = await Product.create({
        name: String(name).trim(),
        description: String(description || "").trim(),
        category: String(category).trim(),
        gender: String(gender).trim(),
        price: Number(price),
        image: imgUrl,
      });

      return res.json({
        id: created._id.toString(),
        name: created.name,
        description: created.description,
        category: created.category,
        gender: created.gender,
        price: created.price,
        image: created.image,
        createdAt: created.createdAt,
      });
    } catch (e) {
      return res.status(500).json({ error: "Failed to add product", details: e.message });
    }
  });
});

app.put("/api/products/:id", requireAdmin, (req, res) => {
  uploadProductImage(req, res, async (err) => {
    try {
      if (err) return res.status(400).json({ error: "Upload error", details: err.message });

      const { name, description = "", category, gender, price } = req.body || {};
      if (!name || !category || !gender || !price) return res.status(400).json({ error: "name, category, gender, price required" });

      const update = {
        name: String(name).trim(),
        description: String(description || "").trim(),
        category: String(category).trim(),
        gender: String(gender).trim(),
        price: Number(price),
      };
      if (req.file) update.image = `${publicBaseUrl(req)}/uploads/${req.file.filename}`;

      const updated = await Product.findByIdAndUpdate(req.params.id, update, { new: true }).lean();
      if (!updated) return res.status(404).json({ error: "Product not found" });

      return res.json({
        id: updated._id.toString(),
        name: updated.name,
        description: updated.description,
        category: updated.category,
        gender: updated.gender,
        price: updated.price,
        image: updated.image,
        createdAt: updated.createdAt,
      });
    } catch (e) {
      return res.status(500).json({ error: "Update failed", details: e.message });
    }
  });
});

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const deleted = await Product.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Product not found" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Delete failed", details: e.message });
  }
});

// ---------- ORDERS ----------
app.post("/api/orders", auth, (req, res) => {
  uploadOrderProof(req, res, async (err) => {
    try {
      if (err) return res.status(400).json({ error: "Upload error", details: err.message });

      const raw = req.body?.items ?? req.body?.cartItems ?? req.body?.products ?? [];
      let items = [];

      if (Array.isArray(raw)) items = raw;
      else {
        try { items = JSON.parse(raw || "[]"); }
        catch { return res.status(400).json({ error: "Invalid items payload (must be JSON array string)" }); }
      }

      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "Cart items required", debug: { gotKeys: Object.keys(req.body || {}) } });
      }

      const fullName = safeTrim(req.body.fullName);
      const phone = safeTrim(req.body.phone);
      const email = safeTrim(req.body.email);
      const address = safeTrim(req.body.address);
      const city = safeTrim(req.body.city);
      const country = safeTrim(req.body.country);
      const notes = safeTrim(req.body.notes);

      const paymentMethod = safeTrim(req.body.paymentMethod || "cash");
      const telebirrRef = safeTrim(req.body.telebirrRef);

      if (!fullName) return res.status(400).json({ error: "Full name required" });
      if (!phone) return res.status(400).json({ error: "Phone required" });
      if (!address) return res.status(400).json({ error: "Address required" });

      const total = items.reduce((sum, it) => sum + (Number(it.price) || 0) * (Number(it.qty) || 1), 0);

      // proof url full
      const proofUrl = req.file ? `${publicBaseUrl(req)}/uploads/${req.file.filename}` : "";

      // ✅ Mobile safety: if someone sends base64 image in order items, replace with product image URL from DB
      const productIds = items.map(it => String(it.productId || "")).filter(Boolean);
      const dbProducts = await Product.find({ _id: { $in: productIds } }).select({ _id: 1, image: 1 }).lean();
      const imageMap = new Map(dbProducts.map(p => [p._id.toString(), p.image || ""]));

      const normalizedItems = items.map(it => {
        const pid = String(it.productId || "");
        const incoming = String(it.image || "");
        const safeImg = isDataUrl(incoming) ? (imageMap.get(pid) || "") : incoming;
        return {
          productId: pid,
          name: String(it.name || ""),
          price: Number(it.price) || 0,
          qty: Number(it.qty) || 1,
          image: safeImg,
        };
      });

      const userObjectId = new mongoose.Types.ObjectId(req.user.id);

      const orderDoc = await Order.create({
        orderId: makeOrderId(),
        userId: userObjectId,
        items: normalizedItems,
        total,
        customer: { fullName, phone, email, address, city, country, notes },
        payment: {
          method: ["cash", "card", "telebirr"].includes(paymentMethod) ? paymentMethod : "cash",
          status: "pending",
          telebirrRef,
          proofUrl,
        },
        status: "placed",
      });

      // ✅ FAST: email owner async (no await)
      if (OWNER_EMAIL) {
        const ownerText = `New Order ✅

Order: ${orderDoc.orderId}
Total: ${orderDoc.total} ETB

Customer:
${orderDoc.customer.fullName} | ${orderDoc.customer.phone}
Email: ${orderDoc.customer.email || "-"}

Address:
${orderDoc.customer.address}

Payment:
${orderDoc.payment.method} | ${orderDoc.payment.status}
TelebirrRef: ${orderDoc.payment.telebirrRef || "-"}
Proof: ${orderDoc.payment.proofUrl || "-"}

Items:
${(orderDoc.items||[]).map(i=>`• ${i.name} x${i.qty} — ${i.price} ETB`).join("\n")}
`;
        sendEmailAsync({ to: OWNER_EMAIL, subject: `New Order ${orderDoc.orderId} (${orderDoc.total} ETB)`, text: ownerText });
      }

      return res.json({
        ok: true,
        message: "✅ Your order has been placed successfully. Thank you for shopping with Sena Fashion!",
        order: {
          orderId: orderDoc.orderId,
          total: orderDoc.total,
          status: orderDoc.status,
          payment: orderDoc.payment,
          createdAt: orderDoc.createdAt,
        },
      });
    } catch (e) {
      return res.status(500).json({ error: "Order failed", details: e.message });
    }
  });
});

app.get("/api/orders/my", auth, async (req, res) => {
  try {
    const userObjectId = new mongoose.Types.ObjectId(req.user.id);
    const orders = await Order.find({ userId: userObjectId }).sort({ createdAt: -1 }).lean();
    res.json(
      orders.map((o) => ({
        orderId: o.orderId,
        status: o.status,
        total: o.total,
        createdAt: o.createdAt,
        items: o.items || [],
        payment: o.payment || {},
      }))
    );
  } catch (e) {
    res.status(500).json({ error: "Failed to load orders", details: e.message });
  }
});

// ---------- ADMIN: VIEW ALL ORDERS ----------
app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).lean();
    res.json(
      orders.map((o) => ({
        id: o._id.toString(),
        orderId: o.orderId,
        status: o.status,
        total: o.total,
        createdAt: o.createdAt,
        items: o.items || [],
        payment: o.payment || {},
        customer: o.customer || {},
      }))
    );
  } catch (e) {
    res.status(500).json({ error: "Failed to load admin orders", details: e.message });
  }
});

// ---------- ADMIN: UPDATE ORDER ----------
app.put("/api/admin/orders/:id", requireAdmin, async (req, res) => {
  try {
    const { status, paymentStatus } = req.body || {};
    const update = {};

    if (status && ["placed","processing","delivered","cancelled"].includes(status)) update.status = status;
    if (paymentStatus && ["pending","paid","failed"].includes(paymentStatus)) update["payment.status"] = paymentStatus;

    const updated = await Order.findByIdAndUpdate(req.params.id, update, { new: true }).lean();
    if (!updated) return res.status(404).json({ error: "Order not found" });

    return res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Update order failed", details: e.message });
  }
});

// ---------- ADMIN: EMAIL CUSTOMER ----------
app.post("/api/admin/orders/:id/email", requireAdmin, async (req, res) => {
  try {
    const { subject, message } = req.body || {};
    const order = await Order.findById(req.params.id).lean();
    if (!order) return res.status(404).json({ error: "Order not found" });

    const to = safeTrim(order.customer?.email || "");
    if (!to) return res.status(400).json({ error: "Customer email is missing for this order" });

    const text = buildCustomerEmailText(order, message || "");
    const result = await sendEmailSafe({
      to,
      subject: subject || `Update on your order ${order.orderId}`,
      text,
    });

    if (!result.ok) return res.status(500).json({ error: "Email failed", details: result.reason });
    return res.json({ ok: true, message: "✅ Email sent successfully to the customer." });
  } catch (e) {
    res.status(500).json({ error: "Email failed", details: e.message });
  }
});

// ---------------- START ----------------
app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
