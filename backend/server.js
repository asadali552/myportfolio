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
app.use(cors());
app.use(express.json());

// =======================
// 🔗 CONNECT MONGODB
// =======================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.log("Mongo Error:", err));

// =======================
// 👤 ADMIN (TEMP)
// =======================
const ADMIN = {
  email: "admin@asad.com",
  password: bcrypt.hashSync("Asad@2k04", 10)
};

// =======================
// 🔐 AUTH MIDDLEWARE
// =======================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "No token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// =======================
// 📦 SCHEMA + MODEL
// =======================
const projectSchema = new mongoose.Schema({
  t: String,
  c: String,
  d: String,
  s: [String],
  img: String,
  u: String
}, { timestamps: true });

const Project = mongoose.model("Project", projectSchema);

// =======================
// 🚀 ROUTES
// =======================

// TEST
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

// 🔑 LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (email !== ADMIN.email) {
    return res.status(401).json({ error: "Invalid email" });
  }

  const isMatch = await bcrypt.compare(password, ADMIN.password);

  if (!isMatch) {
    return res.status(401).json({ error: "Invalid password" });
  }

  const token = jwt.sign(
    { email },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({ token });
});

// 📥 GET ALL PROJECTS (public)
app.get("/projects", async (req, res) => {
  try {
    const projects = await Project.find().sort({ createdAt: -1 });
    res.json(projects);
  } catch {
    res.status(500).json({ error: "Failed to fetch projects" });
  }
});

// ➕ ADD PROJECT (protected)
app.post("/projects", authMiddleware, async (req, res) => {
  try {
    const newProject = new Project(req.body);
    await newProject.save();

    res.json({
      message: "Project saved ✅",
      project: newProject
    });
  } catch {
    res.status(500).json({ error: "Failed to save project" });
  }
});

// ❌ DELETE PROJECT (protected)
app.delete("/projects/:id", authMiddleware, async (req, res) => {
  try {
    await Project.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted ✅" });
  } catch {
    res.status(500).json({ error: "Failed to delete" });
  }
});

// ✏️ UPDATE PROJECT (protected)
app.put("/projects/:id", authMiddleware, async (req, res) => {
  try {
    const updated = await Project.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json(updated);
  } catch {
    res.status(500).json({ error: "Failed to update" });
  }
});

// =======================
// ▶️ START SERVER
// =======================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});