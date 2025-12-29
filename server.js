/**
 * server.js (ALL-IN-ONE, DEBUG + FIX)
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

// ---------- BASIC ----------
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ---------- UPLOADS ----------
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR));

// ---------- ENV CHECK ----------
const {
  PORT = 3000,
  MONGODB_URI,
  ADMIN_API_KEY,
  JWT_SECRET,
  OWNER_EMAIL,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
  PUBLIC_BASE_URL,
} = process.env;

if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in .env (required for login + orders)");
  process.exit(1);
}

// ---------- MONGO ----------
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB error:", err.message);
    process.exit(1);
  });

// ---------- MODELS ----------
const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true, unique: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, required: true, trim: true },
    gender: { type: String, required: true, trim: true },
    price: { type: Number, required: true },
    image: { type: String, default: "" },
  },
  { timestamps: true }
);
const Product = mongoose.model("Product", productSchema);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, required: true, unique: true },

    // IMPORTANT:
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

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
      status: { type: String, enum: ["pending", "paid"], default: "pending" },
      telebirrRef: { type: String, default: "" },
      proofUrl: { type: String, default: "" },
    },

    status: { type: String, enum: ["placed", "processing", "delivered", "cancelled"], default: "placed" },
  },
  { timestamps: true }
);
const Order = mongoose.model("Order", orderSchema);

// ---------- HELPERS ----------
function publicBaseUrl(req) {
  return PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function makeOrderId() {
  return "ORD-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 7).toUpperCase();
}

// ---------- ADMIN MIDDLEWARE ----------
function requireAdmin(req, res, next) {
  if (!ADMIN_API_KEY) return res.status(500).json({ error: "Server missing ADMIN_API_KEY" });
  const key = req.headers["x-admin-key"];
  if (!key || key !== ADMIN_API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// ---------- AUTH MIDDLEWARE (DEBUG) ----------
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  // DEBUG
  console.log("🔎 AUTH header:", header ? "present" : "missing");

  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // DEBUG: show payload keys only
    console.log("🔎 JWT decoded keys:", Object.keys(decoded));

    // We accept several possible payload field names:
    const id = decoded.id || decoded.userId || decoded._id;

    if (!id) return res.status(401).json({ error: "Token missing user id" });

    req.user = { id: String(id) };
    return next();
  } catch (e) {
    console.log("❌ JWT verify error:", e.message);
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------- MULTER ----------
const productStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = (file.originalname || "image").replace(/[^\w.\-]+/g, "_");
    cb(null, Date.now() + "_" + safe);
  },
});
const uploadProductImage = multer({
  storage: productStorage,
  limits: { fileSize: 2 * 1024 * 1024 },
}).single("image");

// Orders proof upload + fix "Field value too long"
const proofStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = (file.originalname || "proof").replace(/[^\w.\-]+/g, "_");
    cb(null, Date.now() + "_proof_" + safe);
  },
});

const uploadOrder = multer({
  storage: proofStorage,
  limits: {
    fileSize: 3 * 1024 * 1024,
    fieldSize: 20 * 1024 * 1024, // ✅ important
    fields: 200,
  },
}).single("paymentProof");

// ---------- EMAIL (OPTIONAL) ----------
function getMailer() {
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;
  const secure = String(SMTP_SECURE || "true").toLowerCase() === "true";
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

async function sendOrderEmailSafe({ to, order, req }) {
  if (!to) return console.warn("⚠️ OWNER_EMAIL missing — skipping email");
  const mailer = getMailer();
  if (!mailer) return console.warn("⚠️ SMTP env missing — skipping email");

  try {
    const items = (order.items || []).map((i) => `• ${i.name} x${i.qty} - ${i.price} ETB`).join("\n");
    const proof = order.payment?.proofUrl ? `${publicBaseUrl(req)}${order.payment.proofUrl}` : "-";

    const text =
`New Order ✅

Order: ${order.orderId}
Total: ${order.total} ETB

Customer:
${order.customer.fullName} | ${order.customer.phone}
${order.customer.address}

Payment:
${order.payment.method} | ${order.payment.status}
TelebirrRef: ${order.payment.telebirrRef || "-"}
Proof: ${proof}

Items:
${items}
`;

    await mailer.sendMail({
      from: SMTP_USER,
      to,
      subject: `New Order ${order.orderId} (${order.total} ETB)`,
      text,
    });

    console.log("✅ Email sent to OWNER_EMAIL");
  } catch (e) {
    console.warn("⚠️ Email failed (order saved):", e.message);
  }
}

// ---------- ROUTES ----------
app.get("/", (req, res) => res.json({ ok: true }));

// AUTH
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

    // IMPORTANT: include id
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

// ✅ TEST TOKEN (THIS WILL TELL US IF TOKEN IS WORKING)
app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id).lean();
  if (!user) return res.status(404).json({ error: "User not found" });
  return res.json({ id: user._id.toString(), fullName: user.fullName, email: user.email });
});

// PRODUCTS
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

      res.json({
        id: created._id.toString(),
        name: created.name,
        description: created.description,
        category: created.category,
        gender: created.gender,
        price: created.price,
        image: created.image,
      });
    } catch (e) {
      res.status(500).json({ error: "Failed to add product", details: e.message });
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

// ORDERS
app.post("/api/orders", auth, (req, res) => {
  uploadOrder(req, res, async (err) => {
    try {
      // DEBUG
      console.log("🧾 /api/orders called. userId from token =", req.user?.id || "MISSING");

      if (err) return res.status(400).json({ error: "Upload error", details: err.message });

      let items = [];
      try {
        items = JSON.parse(req.body.items || "[]");
      } catch {
        return res.status(400).json({ error: "Invalid items JSON" });
      }
      if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "Cart items required" });

      const fullName = (req.body.fullName || "").trim();
      const phone = (req.body.phone || "").trim();
      const email = (req.body.email || "").trim();
      const address = (req.body.address || "").trim();
      const city = (req.body.city || "").trim();
      const country = (req.body.country || "").trim();
      const notes = (req.body.notes || "").trim();

      const paymentMethod = (req.body.paymentMethod || "cash").trim();
      const telebirrRef = (req.body.telebirrRef || "").trim();

      if (!fullName) return res.status(400).json({ error: "Full name required" });
      if (!phone) return res.status(400).json({ error: "Phone required" });
      if (!address) return res.status(400).json({ error: "Address required" });

      const total = items.reduce((sum, it) => sum + (Number(it.price) || 0) * (Number(it.qty) || 1), 0);

      const proofUrl = req.file ? `/uploads/${req.file.filename}` : "";

      // ✅ ensure ObjectId casting works
      const userObjectId = new mongoose.Types.ObjectId(req.user.id);

      const orderDoc = await Order.create({
        orderId: makeOrderId(),
        userId: userObjectId,
        items: items.map((it) => ({
          productId: String(it.productId || ""),
          name: String(it.name || ""),
          price: Number(it.price) || 0,
          qty: Number(it.qty) || 1,
          image: String(it.image || ""),
        })),
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

      await sendOrderEmailSafe({ to: OWNER_EMAIL, order: orderDoc.toObject(), req });

      return res.json({
        ok: true,
        order: { orderId: orderDoc.orderId, total: orderDoc.total, status: orderDoc.status, createdAt: orderDoc.createdAt },
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

// ---------- START ----------
app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
