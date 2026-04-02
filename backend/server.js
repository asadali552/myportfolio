require("dotenv").config();

const express   = require("express");
const cors      = require("cors");
const mongoose  = require("mongoose");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

const app = express();


// ============================================================
// SECURITY MIDDLEWARE
// helmet sets HTTP security headers automatically — one line,
// protects against clickjacking, XSS, content sniffing etc.
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:"],   // data: allows base64 images
      scriptSrc:  ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false, // needed so Google Fonts loads correctly
}));

// Allow requests from any origin — frontend and backend are on different Vercel URLs
app.use(cors({ origin: "*" }));

// 10mb body limit so base64-encoded images fit in the request payload.
// Once you add Cloudinary later, you can drop this back to 1mb.
app.use(express.json({ limit: "10mb" }));


// ============================================================
// RATE LIMITING
// Prevents brute-force attacks and API abuse.
// ============================================================

// Login: only 5 attempts per 15 minutes per IP.
// Makes guessing your password essentially impossible.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many login attempts. Wait 15 minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});

// General API: 100 requests per 15 minutes.
// Stops scrapers and accidental infinite loops from hammering the server.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests. Slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply the general limiter to all routes
// (login gets its own stricter one applied directly on that route)
app.use("/", apiLimiter);


// ============================================================
// DATABASE CONNECTION
// Falls back to local MongoDB if MONGO_URI isn't set in .env
// ============================================================
mongoose
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/portfolioDB")
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.error("Mongo error:", err));


// ============================================================
// ADMIN CREDENTIALS
// Single admin — no registration needed for a personal portfolio.
// Password is hashed at startup so plain text never sits in memory.
// ============================================================
const ADMIN_EMAIL         = process.env.ADMIN_EMAIL    || "admin@asad.com";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(
  process.env.ADMIN_PASSWORD || "Asad@2k04",
  10  // 10 salt rounds — right balance between security and speed
);


// ============================================================
// AUTH MIDDLEWARE
// Protects any route that modifies data.
// Expects a raw JWT in the Authorization header (not "Bearer token", just the token).
// ============================================================
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "Authentication required" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    // Token expired or tampered — tell the frontend to re-login
    return res.status(401).json({ error: "Token invalid or expired. Please login again." });
  }
}


// ============================================================
// INPUT VALIDATION HELPER
// Call this at the top of any route that uses express-validator.
// Returns 422 with error details if any check failed.
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
// 'problem' and 'result' power the featured project case study card.
// The frontend renders them as "What / Problem / Result" lines
// in the big hero project display at the top of the Work section.
const projectSchema = new mongoose.Schema({
  t:       { type: String, required: true, trim: true, maxlength: 120 }, // title
  c:       { type: String, trim: true, maxlength: 60 },                  // category
  d:       { type: String, trim: true, maxlength: 600 },                 // description
  problem: { type: String, trim: true, maxlength: 300 },                 // problem it solved
  result:  { type: String, trim: true, maxlength: 200 },                 // measurable result
  s:       [{ type: String, trim: true, maxlength: 40 }],                // tech stack
  img:     { type: String, default: "" },                                // base64 screenshot
  u:       { type: String, trim: true },                                 // live URL
}, { timestamps: true });
const Project = mongoose.model("Project", projectSchema);


// --- Skills ---
const skillSchema = new mongoose.Schema({
  e: { type: String, trim: true, maxlength: 8 },                  // emoji icon
  n: { type: String, required: true, trim: true, maxlength: 40 }, // name
  l: { type: String, trim: true, maxlength: 40 },                 // level label e.g. "Intermediate"
  p: { type: Number, min: 0, max: 100, default: 50 }              // proficiency %
}, { timestamps: true });
const Skill = mongoose.model("Skill", skillSchema);


// --- Portfolio Info (always a single document) ---
// 'resume' is the Google Drive / PDF URL for the "Resume ↗" nav button.
// The frontend stores it in localStorage after loadInfo() so the button works offline.
const infoSchema = new mongoose.Schema({
  name:   { type: String, default: "Asad Ali" },
  role:   { type: String, default: "Full Stack Developer · SE Student" },
  loc:    { type: String, default: "Karachi, Pakistan" },
  email:  { type: String, default: "connect.asadali8@gmail.com" },
  phone:  { type: String, default: "03171222948" },
  bio:    { type: String, default: "" },
  tag:    { type: String, default: "" },
  stp:    { type: String, default: "5+" },   // projects count in About stats
  fv:     { type: String, default: "" },     // Fiverr URL
  gh:     { type: String, default: "" },     // GitHub URL (also used by sidebar icons)
  li:     { type: String, default: "" },     // LinkedIn URL
  resume: { type: String, default: "" },     // PDF/Drive link for the Resume button
  avatar: { type: String, default: "" },     // base64 profile photo
}, { timestamps: true });
const Info = mongoose.model("Info", infoSchema);


// --- Contact Messages ---
// Every contact form submission gets saved here alongside Formspree.
// Gives you a permanent searchable inbox you own.
const messageSchema = new mongoose.Schema({
  name:         { type: String, trim: true },
  email:        { type: String, trim: true },
  project_type: { type: String, trim: true },
  message:      { type: String, trim: true },
  read:         { type: Boolean, default: false }, // reserved for future "mark as read"
}, { timestamps: true });
const Message = mongoose.model("Message", messageSchema);


// --- Analytics ---
// One document per calendar day, keyed by "YYYY-MM-DD".
// Incremented by the frontend silently on every page load.
const analyticsSchema = new mongoose.Schema({
  date:   { type: String, required: true, unique: true },
  visits: { type: Number, default: 0 },
}, { timestamps: false });
const Analytics = mongoose.model("Analytics", analyticsSchema);


// --- Articles ---
// Content uses plain text with markdown-style formatting.
// The frontend parser handles ## headings, **bold**, `code`, > blockquotes, - lists.
const articleSchema = new mongoose.Schema({
  t:         { type: String, required: true, trim: true, maxlength: 200 }, // title
  c:         { type: String, trim: true, maxlength: 60 },                  // category
  r:         { type: String, trim: true, maxlength: 30 },                  // read time label
  e:         { type: String, trim: true, maxlength: 300 },                 // excerpt for card
  body:      { type: String },                                             // full content
  published: { type: Boolean, default: true },
}, { timestamps: true });
const Article = mongoose.model("Article", articleSchema);


// ============================================================
// ROUTES
// ============================================================

// Health check — verify the deployment is alive
app.get("/", (req, res) => res.send("Portfolio backend running 🚀"));


// ─── AUTH ─────────────────────────────────────────────────────

// POST /login — loginLimiter is stricter than the general one
app.post("/login", loginLimiter, [
  body("email").isEmail().normalizeEmail(),
  body("password").notEmpty().trim(),
], async (req, res) => {
  if (!validate(req, res)) return;
  const { email, password } = req.body;

  // Same error for wrong email OR wrong password —
  // never reveal which one was incorrect to an attacker
  if (email !== ADMIN_EMAIL) return res.status(401).json({ error: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
});


// ─── INFO ─────────────────────────────────────────────────────

// GET /info — public, called on every page load to populate the portfolio
app.get("/info", async (req, res) => {
  try {
    let info = await Info.findOne();
    if (!info) info = await Info.create({}); // first run: creates with schema defaults
    res.json(info);
  } catch { res.status(500).json({ error: "Failed to fetch info" }); }
});

// PUT /info — protected
// Whitelist approach: only updates fields in the allowed list, ignores everything else
app.put("/info", auth, [
  body("name").optional().trim().isLength({ max: 80 }),
  body("email").optional().isEmail().normalizeEmail(),
  body("phone").optional().trim().isLength({ max: 20 }),
  body("resume").optional().trim(), // accepts URL or empty string
], async (req, res) => {
  if (!validate(req, res)) return;
  try {
    // 'resume' is in this list — that's what makes the Resume button work
    const allowed = ["name","role","loc","email","phone","bio","tag","stp","fv","gh","li","resume","avatar"];
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

// GET /skills — public, sorted by creation date for consistent card order
app.get("/skills", async (req, res) => {
  try {
    res.json(await Skill.find().sort({ createdAt: 1 }));
  } catch { res.status(500).json({ error: "Failed to fetch skills" }); }
});

app.post("/skills", auth, [
  body("n").notEmpty().trim().isLength({ max: 40 }).withMessage("Skill name required"),
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

// GET /projects — public, newest first so latest work shows at top
app.get("/projects", async (req, res) => {
  try {
    res.json(await Project.find().sort({ createdAt: -1 }));
  } catch { res.status(500).json({ error: "Failed to fetch projects" }); }
});

// POST /projects — saves 'problem' and 'result' for the featured case study card
app.post("/projects", auth, [
  body("t").notEmpty().trim().isLength({ max: 120 }).withMessage("Title required"),
  body("u").optional().isURL(),
], async (req, res) => {
  if (!validate(req, res)) return;
  try {
    const { t, c, d, problem, result, s, img, u } = req.body;
    res.json({ project: await Project.create({ t, c, d, problem, result, s, img: img || "", u }) });
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

// POST /messages — public, called from the contact form alongside Formspree
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

// GET /messages — protected admin view
app.get("/messages", auth, async (req, res) => {
  try {
    res.json(await Message.find().sort({ createdAt: -1 }));
  } catch { res.status(500).json({ error: "Failed to fetch messages" }); }
});


// ─── ANALYTICS ──────────────────────────────────────────────

// POST /analytics/hit — public, called silently on every page load
// Upsert: create today's document if it doesn't exist, else increment visits
app.post("/analytics/hit", async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10); // "2025-01-15"
    await Analytics.findOneAndUpdate(
      { date: today },
      { $inc: { visits: 1 } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Analytics failed" }); }
});

// GET /analytics — protected, powers the admin Analytics tab
app.get("/analytics", auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1); // Monday

    const monthStart = new Date();
    monthStart.setDate(1);

    const fmt = d => d.toISOString().slice(0, 10);
    const all = await Analytics.find();

    res.json({
      totalVisits: all.reduce((sum, d) => sum + d.visits, 0),
      todayVisits: all.find(d => d.date === today)?.visits || 0,
      thisWeek:    all.filter(d => d.date >= fmt(weekStart)).reduce((s, d) => s + d.visits, 0),
      thisMonth:   all.filter(d => d.date >= fmt(monthStart)).reduce((s, d) => s + d.visits, 0),
    });
  } catch { res.status(500).json({ error: "Failed to fetch analytics" }); }
});


// ─── ARTICLES ───────────────────────────────────────────────

// GET /articles — public, only published, newest first
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
// PORT from environment so Vercel/Render injects their own
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on port ${PORT} 🚀`));

module.exports = app;