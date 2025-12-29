require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// -------------------
// CORS
// -------------------
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-admin-key", "Authorization"],
  })
);
app.options(/.*/, cors());

// JSON for non-multipart endpoints
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const { MONGODB_URI, ADMIN_API_KEY, JWT_SECRET } = process.env;

if (!MONGODB_URI) console.error("❌ Missing MONGODB_URI in env");
if (!ADMIN_API_KEY) console.error("❌ Missing ADMIN_API_KEY in env");
if (!JWT_SECRET) console.error("❌ Missing JWT_SECRET in env");

// -------------------
// MongoDB Connect
// -------------------
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

// -------------------
// Schemas
// -------------------
const productSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true }, // our custom id
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

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    fullName: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "users" }
);

const orderSchema = new mongoose.Schema(
  {
    orderId: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: "User" },
    items: [
      {
        productId: String,
        name: String,
        price: Number,
        qty: Number,
        image: String,
      },
    ],
    subtotal: Number,
    shippingFee: Number,
    total: Number,

    customer: {
      fullName: String,
      email: String,
      phone: String,
      address: String,
      city: String,
      country: String,
      notes: String,
    },

    payment: {
      method: { type: String, default: "cash" }, // card | telebirr | cash
      status: { type: String, default: "pending" }, // pending | confirmed
      telebirrRef: { type: String, default: "" },
      proofImageBase64: { type: String, default: "" }, // optional upload
    },

    status: { type: String, default: "placed" }, // placed | processing | delivered | cancelled
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "orders" }
);

const Product = mongoose.model("Product", productSchema);
const User = mongoose.model("User", userSchema);
const Order = mongoose.model("Order", orderSchema);

// -------------------
// Multer (memory) for product images + payment proof upload
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
// Customer Auth (JWT)
// -------------------
function signToken(user) {
  return jwt.sign(
    { uid: user._id.toString(), email: user.email },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function requireUser(req, res, next) {
  try {
    const auth = req.header("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Missing token" });

    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { uid, email }
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
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

function makeOrderId() {
  return "ORD-" + Date.now().toString() + "-" + crypto.randomBytes(2).toString("hex").toUpperCase();
}

function validateProductFields(body) {
  if (!body.name) return "Product name is required";
  if (!body.category) return "Category is required";
  if (!body.gender) return "Gender is required";
  const price = Number(body.price);
  if (Number.isNaN(price)) return "Price must be a number";
  return null;
}

// -------------------
// Routes
// -------------------
app.get("/", (req, res) => res.send("✅ Fashion backend running"));
app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- PRODUCTS ----------
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
    const msg = validateProductFields(req.body);
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

// ---------- AUTH ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, fullName } = req.body || {};
    const em = String(email || "").trim().toLowerCase();
    const pw = String(password || "");
    const fn = String(fullName || "").trim();

    if (!em) return res.status(400).json({ error: "Email is required" });
    if (!pw || pw.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    const exists = await User.findOne({ email: em }).lean();
    if (exists) return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(pw, 10);
    const user = await User.create({ email: em, passwordHash, fullName: fn });

    const token = signToken(user);
    res.json({ ok: true, token, user: { email: user.email, fullName: user.fullName } });
  } catch (err) {
    res.status(500).json({ error: "Register failed", details: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const em = String(email || "").trim().toLowerCase();
    const pw = String(password || "");

    if (!em || !pw) return res.status(400).json({ error: "Email and password are required" });

    const user = await User.findOne({ email: em });
    if (!user) return res.status(401).json({ error: "Invalid email or password" });

    const ok = await bcrypt.compare(pw, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });

    const token = signToken(user);
    res.json({ ok: true, token, user: { email: user.email, fullName: user.fullName } });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

app.get("/api/me", requireUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.uid).lean();
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ ok: true, user: { email: user.email, fullName: user.fullName } });
  } catch (err) {
    res.status(500).json({ error: "Failed to load profile", details: err.message });
  }
});

// ---------- ORDERS ----------
app.post("/api/orders", requireUser, upload.single("paymentProof"), async (req, res) => {
  try {
    const body = req.body || {};
    const items = JSON.parse(body.items || "[]");
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Cart items are required" });
    }

    // customer info
    const customer = {
      fullName: String(body.fullName || "").trim(),
      email: String(body.email || "").trim(),
      phone: String(body.phone || "").trim(),
      address: String(body.address || "").trim(),
      city: String(body.city || "").trim(),
      country: String(body.country || "").trim(),
      notes: String(body.notes || "").trim(),
    };

    if (!customer.fullName) return res.status(400).json({ error: "Full name is required" });
    if (!customer.phone) return res.status(400).json({ error: "Phone is required" });
    if (!customer.address) return res.status(400).json({ error: "Address is required" });

    const paymentMethod = String(body.paymentMethod || "cash");
    const telebirrRef = String(body.telebirrRef || "").trim();

    let proofImageBase64 = "";
    if (req.file) {
      const mime = req.file.mimetype || "image/png";
      const ext = extFromMime(mime);
      const b64 = req.file.buffer.toString("base64");
      proofImageBase64 = `data:image/${ext};base64,${b64}`;
    }

    // totals
    const subtotal = items.reduce((s, it) => s + (Number(it.price) || 0) * (Number(it.qty) || 1), 0);
    const shippingFee = 0; // you can change later
    const total = subtotal + shippingFee;

    const order = await Order.create({
      orderId: makeOrderId(),
      userId: req.user.uid,
      items: items.map((it) => ({
        productId: String(it.productId || it.id || ""),
        name: String(it.name || ""),
        price: Number(it.price) || 0,
        qty: Number(it.qty) || 1,
        image: String(it.image || ""),
      })),
      subtotal,
      shippingFee,
      total,
      customer,
      payment: {
        method: paymentMethod,
        status: paymentMethod === "telebirr" ? "pending" : "pending",
        telebirrRef: telebirrRef,
        proofImageBase64,
      },
      status: "placed",
      createdAt: new Date(),
    });

    res.json({ ok: true, order });
  } catch (err) {
    res.status(500).json({ error: "Failed to place order", details: err.message });
  }
});

app.get("/api/orders/my", requireUser, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.uid }).sort({ createdAt: -1 }).lean();
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: "Failed to load orders", details: err.message });
  }
});

// -------------------
// Start server
// -------------------
app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
