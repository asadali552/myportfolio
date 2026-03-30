require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// =======================
// 🔧 MIDDLEWARE
// =======================
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" })); // increased for base64 images

// =======================
// 🔗 CONNECT MONGODB
// =======================
mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/portfolioDB")
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.log("Mongo Error:", err));

// =======================
// 👤 ADMIN (single admin, password in env)
// =======================
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@asad.com";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD || "Asad@2k04", 10);

// =======================
// 🔐 AUTH MIDDLEWARE
// =======================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// =======================
// 📦 SCHEMAS + MODELS
// =======================

// Projects
const projectSchema = new mongoose.Schema({
  t: String,  // title
  c: String,  // category
  d: String,  // description
  s: [String], // stack
  img: String, // base64 or url
  u: String   // live url
}, { timestamps: true });
const Project = mongoose.model("Project", projectSchema);

// Skills
const skillSchema = new mongoose.Schema({
  e: String,  // emoji
  n: String,  // name
  l: String,  // level label
  p: Number   // percentage
}, { timestamps: true });
const Skill = mongoose.model("Skill", skillSchema);

// Portfolio Info (single document)
const infoSchema = new mongoose.Schema({
  name: { type: String, default: "Asad Ali" },
  role: { type: String, default: "Web Developer · SE Student" },
  loc:  { type: String, default: "Karachi, Pakistan" },
  email: { type: String, default: "connect.asadali8@gmail.com" },
  phone: { type: String, default: "03171222948" },
  bio:  { type: String, default: "I'm a Software Engineering student at NUCES–FAST (2nd semester)." },
  tag:  { type: String, default: "" },
  stp:  { type: String, default: "5+" },
  fv:   { type: String, default: "" }, // fiverr url
  gh:   { type: String, default: "" }, // github url
  li:   { type: String, default: "" }, // linkedin url
  avatar: { type: String, default: "" } // base64
}, { timestamps: true });
const Info = mongoose.model("Info", infoSchema);

// =======================
// 🚀 ROUTES
// =======================

// TEST
app.get("/", (req, res) => res.send("Backend is running 🚀"));

// ─── AUTH ─────────────────────────────────────────────

// 🔑 LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });
  if (email !== ADMIN_EMAIL) return res.status(401).json({ error: "Invalid credentials" });
  const isMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
});

// ─── INFO ─────────────────────────────────────────────

// GET portfolio info (public)
app.get("/info", async (req, res) => {
  try {
    let info = await Info.findOne();
    if (!info) info = await Info.create({});
    res.json(info);
  } catch {
    res.status(500).json({ error: "Failed to fetch info" });
  }
});

// UPDATE portfolio info (protected)
app.put("/info", authMiddleware, async (req, res) => {
  try {
    const allowed = ["name","role","loc","email","phone","bio","tag","stp","fv","gh","li","avatar"];
    const update = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });

    let info = await Info.findOne();
    if (!info) info = await Info.create(update);
    else {
      Object.assign(info, update);
      await info.save();
    }
    res.json({ message: "Info updated ✅", info });
  } catch {
    res.status(500).json({ error: "Failed to update info" });
  }
});

// ─── SKILLS ───────────────────────────────────────────

// GET all skills (public)
app.get("/skills", async (req, res) => {
  try {
    const skills = await Skill.find().sort({ createdAt: 1 });
    res.json(skills);
  } catch {
    res.status(500).json({ error: "Failed to fetch skills" });
  }
});

// ADD skill (protected)
app.post("/skills", authMiddleware, async (req, res) => {
  try {
    const { e, n, l, p } = req.body;
    if (!n) return res.status(400).json({ error: "Skill name required" });
    const skill = await Skill.create({ e, n, l, p: Number(p) || 50 });
    res.json({ message: "Skill added ✅", skill });
  } catch {
    res.status(500).json({ error: "Failed to add skill" });
  }
});

// DELETE skill (protected)
app.delete("/skills/:id", authMiddleware, async (req, res) => {
  try {
    await Skill.findByIdAndDelete(req.params.id);
    res.json({ message: "Skill deleted ✅" });
  } catch {
    res.status(500).json({ error: "Failed to delete skill" });
  }
});

// UPDATE skill (protected)
app.put("/skills/:id", authMiddleware, async (req, res) => {
  try {
    const updated = await Skill.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch {
    res.status(500).json({ error: "Failed to update skill" });
  }
});

// ─── PROJECTS ─────────────────────────────────────────

// GET all projects (public)
app.get("/projects", async (req, res) => {
  try {
    const projects = await Project.find().sort({ createdAt: -1 });
    res.json(projects);
  } catch {
    res.status(500).json({ error: "Failed to fetch projects" });
  }
});

// ADD project (protected)
app.post("/projects", authMiddleware, async (req, res) => {
  try {
    const { t, c, d, s, img, u } = req.body;
    if (!t) return res.status(400).json({ error: "Project title required" });
    const project = await Project.create({ t, c, d, s, img, u });
    res.json({ message: "Project saved ✅", project });
  } catch {
    res.status(500).json({ error: "Failed to save project" });
  }
});

// DELETE project (protected)
app.delete("/projects/:id", authMiddleware, async (req, res) => {
  try {
    await Project.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted ✅" });
  } catch {
    res.status(500).json({ error: "Failed to delete" });
  }
});

// UPDATE project (protected)
app.put("/projects/:id", authMiddleware, async (req, res) => {
  try {
    const updated = await Project.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch {
    res.status(500).json({ error: "Failed to update" });
  }
});

// =======================
// ▶️ START SERVER
// =======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;