require("dotenv").config();

const express    = require("express");
const cors       = require("cors");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

const app = express();


// ============================================================
// SECURITY MIDDLEWARE
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:"],
      scriptSrc:  ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({ origin: "*" }));

// 10mb limit to allow base64 images in request body
app.use(express.json({ limit: "10mb" }));


// ============================================================
// RATE LIMITING
// ============================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many login attempts. Wait 15 minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests. Slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/", apiLimiter);


// ============================================================
// DATABASE CONNECTION
// ============================================================
mongoose
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/portfolioDB")
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.error("Mongo error:", err));


// ============================================================
// ADMIN CREDENTIALS
// ============================================================
const ADMIN_EMAIL         = process.env.ADMIN_EMAIL    || "admin@asad.com";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(
  process.env.ADMIN_PASSWORD || "Asad@2k04",
  10
);


// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token invalid or expired. Please login again." });
  }
}


// ============================================================
// INPUT VALIDATION HELPER
// ============================================================
function validate(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(422).json({ errors: errors.array() });
    return false;
  }
  return true;
}


// ============================================================
// SCHEMAS + MODELS
// ============================================================

// --- Projects ---
// img stores base64 string directly in MongoDB
const projectSchema = new mongoose.Schema({
  t:   { type: String, required: true, trim: true, maxlength: 120 },
  c:   { type: String, trim: true, maxlength: 60 },
  d:   { type: String, trim: true, maxlength: 600 },
  s:   [{ type: String, trim: true, maxlength: 40 }],
  img: { type: String, default: "" }, // base64 string
  u:   { type: String, trim: true },
}, { timestamps: true });
const Project = mongoose.model("Project", projectSchema);


// --- Skills ---
const skillSchema = new mongoose.Schema({
  e: { type: String, trim: true, maxlength: 8 },
  n: { type: String, required: true, trim: true, maxlength: 40 },
  l: { type: String, trim: true, maxlength: 40 },
  p: { type: Number, min: 0, max: 100, default: 50 }
}, { timestamps: true });
const Skill = mongoose.model("Skill", skillSchema);


// --- Portfolio Info (single document) ---
// avatar stores base64 string directly in MongoDB
const infoSchema = new mongoose.Schema({
  name:   { type: String, default: "Asad Ali" },
  role:   { type: String, default: "Web Developer · SE Student" },
  loc:    { type: String, default: "Karachi, Pakistan" },
  email:  { type: String, default: "connect.asadali8@gmail.com" },
  phone:  { type: String, default: "03171222948" },
  bio:    { type: String, default: "" },
  tag:    { type: String, default: "" },
  stp:    { type: String, default: "5+" },
  fv:     { type: String, default: "" },
  gh:     { type: String, default: "" },
  li:     { type: String, default: "" },
  avatar: { type: String, default: "" }, // base64 string
}, { timestamps: true });
const Info = mongoose.model("Info", infoSchema);


// --- Contact Messages ---
const messageSchema = new mongoose.Schema({
  name:         { type: String, trim: true },
  email:        { type: String, trim: true },
  project_type: { type: String, trim: true },
  message:      { type: String, trim: true },
  read:         { type: Boolean, default: false },
}, { timestamps: true });
const Message = mongoose.model("Message", messageSchema);


// --- Analytics ---
const analyticsSchema = new mongoose.Schema({
  date:   { type: String, required: true, unique: true },
  visits: { type: Number, default: 0 },
}, { timestamps: false });
const Analytics = mongoose.model("Analytics", analyticsSchema);


// --- Articles ---
const articleSchema = new mongoose.Schema({
  t:    { type: String, required: true, trim: true, maxlength: 200 },
  c:    { type: String, trim: true, maxlength: 60 },
  r:    { type: String, trim: true, maxlength: 30 },
  e:    { type: String, trim: true, maxlength: 300 },
  body: { type: String },
  published: { type: Boolean, default: true },
}, { timestamps: true });
const Article = mongoose.model("Article", articleSchema);


// ============================================================
// ROUTES
// ============================================================

// Health check
app.get("/", (req, res) => res.send("Portfolio backend running 🚀"));


// ─── AUTH ─────────────────────────────────────────────────────

app.post("/login", loginLimiter, [
  body("email").isEmail().normalizeEmail(),
  body("password").notEmpty().trim(),
], async (req, res) => {
  if (!validate(req, res)) return;
  const { email, password } = req.body;

  if (email !== ADMIN_EMAIL) return res.status(401).json({ error: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
});


// ─── INFO ─────────────────────────────────────────────────────

app.get("/info", async (req, res) => {
  try {
    let info = await Info.findOne();
    if (!info) info = await Info.create({});
    res.json(info);
  } catch { res.status(500).json({ error: "Failed to fetch info" }); }
});

// PUT /info — saves avatar as base64 directly, no Cloudinary
app.put("/info", auth, [
  body("name").optional().trim().isLength({ max: 80 }),
  body("email").optional().isEmail().normalizeEmail(),
  body("phone").optional().trim().isLength({ max: 20 }),
], async (req, res) => {
  if (!validate(req, res)) return;
  try {
    const allowed = ["name","role","loc","email","phone","bio","tag","stp","fv","gh","li","avatar"];
    const update  = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });

    let info = await Info.findOne();
    if (!info) { info = await Info.create(update); }
    else { Object.assign(info, update); await info.save(); }

    res.json({ message: "Info updated ✅", info });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update info" });
  }
});


// ─── SKILLS ─────────────────────────────────────────────────

app.get("/skills", async (req, res) => {
  try {
    res.json(await Skill.find().sort({ createdAt: 1 }));
  } catch { res.status(500).json({ error: "Failed to fetch skills" }); }
});

app.post("/skills", auth, [
  body("n").notEmpty().trim().isLength({ max: 40 }).withMessage("Skill name required (max 40 chars)"),
  body("p").optional().isInt({ min: 0, max: 100 }),
], async (req, res) => {
  if (!validate(req, res)) return;
  try {
    const { e, n, l, p } = req.body;
    res.json({ skill: await Skill.create({ e, n, l, p: Number(p) || 50 }) });
  } catch { res.status(500).json({ error: "Failed to add skill" }); }
});

app.delete("/skills/:id", auth, async (req, res) => {
  try {
    await Skill.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted ✅" });
  } catch { res.status(500).json({ error: "Failed to delete" }); }
});

app.put("/skills/:id", auth, async (req, res) => {
  try {
    res.json(await Skill.findByIdAndUpdate(req.params.id, req.body, { new: true }));
  } catch { res.status(500).json({ error: "Failed to update" }); }
});


// ─── PROJECTS ───────────────────────────────────────────────

app.get("/projects", async (req, res) => {
  try {
    res.json(await Project.find().sort({ createdAt: -1 }));
  } catch { res.status(500).json({ error: "Failed to fetch projects" }); }
});

// POST /projects — saves screenshot as base64 directly in MongoDB
app.post("/projects", auth, [
  body("t").notEmpty().trim().isLength({ max: 120 }).withMessage("Title required"),
  body("u").optional().isURL(),
], async (req, res) => {
  if (!validate(req, res)) return;
  try {
    const { t, c, d, s, img, u } = req.body;
    res.json({ project: await Project.create({ t, c, d, s, img: img || "", u }) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save project" });
  }
});

app.delete("/projects/:id", auth, async (req, res) => {
  try {
    await Project.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted ✅" });
  } catch { res.status(500).json({ error: "Failed to delete" }); }
});

app.put("/projects/:id", auth, async (req, res) => {
  try {
    res.json(await Project.findByIdAndUpdate(req.params.id, req.body, { new: true }));
  } catch { res.status(500).json({ error: "Failed to update" }); }
});


// ─── MESSAGES ───────────────────────────────────────────────

app.post("/messages", [
  body("name").trim().isLength({ max: 100 }),
  body("email").isEmail().normalizeEmail(),
  body("message").notEmpty().trim().isLength({ max: 2000 }),
], async (req, res) => {
  if (!validate(req, res)) return;
  try {
    const { name, email, project_type, message } = req.body;
    await Message.create({ name, email, project_type, message });
    res.json({ message: "Message saved ✅" });
  } catch { res.status(500).json({ error: "Failed to save message" }); }
});

app.get("/messages", auth, async (req, res) => {
  try {
    res.json(await Message.find().sort({ createdAt: -1 }));
  } catch { res.status(500).json({ error: "Failed to fetch messages" }); }
});


// ─── ANALYTICS ──────────────────────────────────────────────

app.post("/analytics/hit", async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    await Analytics.findOneAndUpdate(
      { date: today },
      { $inc: { visits: 1 } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Analytics failed" }); }
});

app.get("/analytics", auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1);

    const monthStart = new Date();
    monthStart.setDate(1);

    const fmt = d => d.toISOString().slice(0, 10);

    const all = await Analytics.find();
    const total = all.reduce((sum, d) => sum + d.visits, 0);

    const todayDoc = all.find(d => d.date === today);
    const week  = all.filter(d => d.date >= fmt(weekStart)).reduce((s,d)=>s+d.visits,0);
    const month = all.filter(d => d.date >= fmt(monthStart)).reduce((s,d)=>s+d.visits,0);

    res.json({
      totalVisits:  total,
      todayVisits:  todayDoc?.visits || 0,
      thisWeek:     week,
      thisMonth:    month,
    });
  } catch { res.status(500).json({ error: "Failed to fetch analytics" }); }
});


// ─── ARTICLES ───────────────────────────────────────────────

app.get("/articles", async (req, res) => {
  try {
    res.json(await Article.find({ published: true }).sort({ createdAt: -1 }));
  } catch { res.status(500).json({ error: "Failed to fetch articles" }); }
});

app.post("/articles", auth, [
  body("t").notEmpty().trim().isLength({ max: 200 }).withMessage("Title required"),
  body("body").notEmpty().withMessage("Article content required"),
], async (req, res) => {
  if (!validate(req, res)) return;
  try {
    const { t, c, r, e, body: content } = req.body;
    res.json({ article: await Article.create({ t, c, r, e, body: content }) });
  } catch { res.status(500).json({ error: "Failed to create article" }); }
});

app.delete("/articles/:id", auth, async (req, res) => {
  try {
    await Article.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted ✅" });
  } catch { res.status(500).json({ error: "Failed to delete" }); }
});

app.put("/articles/:id", auth, async (req, res) => {
  try {
    res.json(await Article.findByIdAndUpdate(req.params.id, req.body, { new: true }));
  } catch { res.status(500).json({ error: "Failed to update" }); }
});


// ============================================================
// START SERVER
// ============================================================
module.exports = app;