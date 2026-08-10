require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

const app = express();

// ============================================================
// ENV CHECK
// ============================================================

const requiredEnv = [
  "MONGO_URI",
  "ADMIN_EMAIL",
  "JWT_SECRET",
  "ALLOWED_ORIGINS"
];

const missingEnv = requiredEnv.filter((key) => !process.env[key]);

if (!process.env.ADMIN_PASSWORD && !process.env.ADMIN_PASSWORD_HASH) {
  missingEnv.push("ADMIN_PASSWORD or ADMIN_PASSWORD_HASH");
}

if (process.env.NODE_ENV === "production" && missingEnv.length) {
  throw new Error(
    `Missing required environment variables: ${missingEnv.join(", ")}`
  );
}

// ============================================================
// SECURITY
// ============================================================

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

// ============================================================
// CORS
// ============================================================

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    },

    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.options("/*splat", cors());

// ============================================================
// BODY PARSER
// ============================================================

app.use(express.json({ limit: "10mb" }));

// ============================================================
// RATE LIMITING
// ============================================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    error: "Too many login attempts. Wait 15 minutes and try again."
  },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: "Too many requests. Slow down."
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(apiLimiter);

// ============================================================
// DATABASE
// ============================================================

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch((err) => {
    console.error("MongoDB connection failed:", err);
  });

// ============================================================
// ADMIN CREDENTIALS
// ============================================================

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "")
  .trim()
  .toLowerCase();

const ADMIN_PASSWORD_HASH =
  process.env.ADMIN_PASSWORD_HASH ||
  (process.env.ADMIN_PASSWORD
    ? bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12)
    : null);

const JWT_SECRET = process.env.JWT_SECRET;

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function auth(req, res, next) {
  const [scheme, token] = (req.headers.authorization || "").split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Token invalid or expired. Please login again."
    });
  }
}

// ============================================================
// VALIDATION
// ============================================================

function validate(req, res) {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.status(422).json({
      errors: errors.array()
    });

    return false;
  }

  return true;
}

// ============================================================
// MODELS
// ============================================================

const projectSchema = new mongoose.Schema(
  {
    t: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120
    },

    c: {
      type: String,
      trim: true,
      maxlength: 60
    },

    d: {
      type: String,
      trim: true,
      maxlength: 600
    },

    problem: {
      type: String,
      trim: true,
      maxlength: 300
    },

    result: {
      type: String,
      trim: true,
      maxlength: 200
    },

    s: [
      {
        type: String,
        trim: true,
        maxlength: 40
      }
    ],

    img: {
      type: String,
      default: ""
    },

    u: {
      type: String,
      trim: true
    }
  },
  { timestamps: true }
);

const Project = mongoose.model("Project", projectSchema);

const skillSchema = new mongoose.Schema(
  {
    e: {
      type: String,
      trim: true,
      maxlength: 8
    },

    n: {
      type: String,
      required: true,
      trim: true,
      maxlength: 40
    },

    l: {
      type: String,
      trim: true,
      maxlength: 40
    },

    p: {
      type: Number,
      min: 0,
      max: 100,
      default: 50
    },

    cat: {
      type: String,
      trim: true,
      maxlength: 60,
      default: ""
    }
  },
  { timestamps: true }
);

const Skill = mongoose.model("Skill", skillSchema);

const infoSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      default: "Asad Ali"
    },

    role: {
      type: String,
      default: "Full Stack Developer · SE Student"
    },

    loc: {
      type: String,
      default: "Karachi, Pakistan"
    },

    email: {
      type: String,
      default: "connect.asadali8@gmail.com"
    },

    phone: {
      type: String,
      default: "03171222948"
    },

    bio: {
      type: String,
      default: ""
    },

    aboutDesc: {
      type: String,
      default: ""
    },

    tag: {
      type: String,
      default: ""
    },

    stp: {
      type: String,
      default: "5+"
    },

    fv: {
      type: String,
      default: ""
    },

    gh: {
      type: String,
      default: ""
    },

    li: {
      type: String,
      default: ""
    },

    resume: {
      type: String,
      default: ""
    },

    avatar: {
      type: String,
      default: ""
    },

    currently: {
      type: [
        {
          type: String,
          trim: true
        }
      ],
      default: []
    },

    gigs: {
      type: [
        {
          type: String,
          trim: true
        }
      ],
      default: []
    }
  },
  { timestamps: true }
);

const Info = mongoose.model("Info", infoSchema);

const messageSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true
    },

    email: {
      type: String,
      trim: true
    },

    project_type: {
      type: String,
      trim: true
    },

    message: {
      type: String,
      trim: true
    },

    read: {
      type: Boolean,
      default: false
    }
  },
  { timestamps: true }
);

const Message = mongoose.model("Message", messageSchema);

const analyticsSchema = new mongoose.Schema(
  {
    date: {
      type: String,
      required: true,
      unique: true
    },

    visits: {
      type: Number,
      default: 0
    }
  },
  { timestamps: false }
);

const Analytics = mongoose.model("Analytics", analyticsSchema);

const articleSchema = new mongoose.Schema(
  {
    t: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200
    },

    c: {
      type: String,
      trim: true,
      maxlength: 60
    },

    r: {
      type: String,
      trim: true,
      maxlength: 30
    },

    e: {
      type: String,
      trim: true,
      maxlength: 300
    },

    body: {
      type: String
    },

    published: {
      type: Boolean,
      default: true
    }
  },
  { timestamps: true }
);

const Article = mongoose.model("Article", articleSchema);

// ============================================================
// HEALTH
// ============================================================

app.get("/", (req, res) => {
  res.send("Portfolio backend running 🚀");
});

// ============================================================
// LOGIN
// ============================================================

app.post(
  "/login",
  loginLimiter,
  [
    body("email").trim().toLowerCase().isEmail(),
    body("password").notEmpty()
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    const email = req.body.email;
    const password = req.body.password;

    if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH) {
      return res.status(500).json({
        error: "Admin credentials are not configured"
      });
    }

    if (email !== ADMIN_EMAIL) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      ADMIN_PASSWORD_HASH
    );

    if (!isMatch) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    const token = jwt.sign(
      {
        email,
        role: "admin"
      },
      JWT_SECRET,
      {
        expiresIn: "2h"
      }
    );

    res.json({ token });
  }
);

// ============================================================
// INFO
// ============================================================

app.get("/info", async (req, res) => {
  try {
    let info = await Info.findOne();

    if (!info) {
      info = await Info.create({});
    }

    res.json(info);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to fetch info"
    });
  }
});

app.put(
  "/info",
  auth,
  [
    body("name").optional().trim().isLength({ max: 80 }),
    body("email").optional().trim().toLowerCase().isEmail(),
    body("phone").optional().trim().isLength({ max: 20 }),
    body("resume").optional().trim()
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const allowed = [
        "name",
        "role",
        "loc",
        "email",
        "phone",
        "bio",
        "aboutDesc",
        "tag",
        "stp",
        "fv",
        "gh",
        "li",
        "resume",
        "avatar",
        "currently",
        "gigs"
      ];

      const update = {};

      allowed.forEach((key) => {
        if (req.body[key] !== undefined) {
          update[key] = req.body[key];
        }
      });

      let info = await Info.findOne();

      if (!info) {
        info = await Info.create(update);
      } else {
        Object.assign(info, update);
        await info.save();
      }

      res.json({
        message: "Info updated ✅",
        info
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Failed to update info"
      });
    }
  }
);

// ============================================================
// SKILLS
// ============================================================

app.get("/skills", async (req, res) => {
  try {
    const skills = await Skill.find().sort({
      createdAt: 1
    });

    res.json(skills);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to fetch skills"
    });
  }
});

app.post(
  "/skills",
  auth,
  [
    body("n")
      .notEmpty()
      .trim()
      .isLength({ max: 40 }),

    body("p")
      .optional()
      .isInt({ min: 0, max: 100 })
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const {
        e,
        n,
        l,
        p,
        cat
      } = req.body;

      const skill = await Skill.create({
        e,
        n,
        l,
        p: Number(p) || 50,
        cat: cat || ""
      });

      res.json({ skill });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Failed to add skill"
      });
    }
  }
);

app.delete("/skills/:id", auth, async (req, res) => {
  try {
    await Skill.findByIdAndDelete(req.params.id);

    res.json({
      message: "Deleted ✅"
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to delete"
    });
  }
});

app.put("/skills/:id", auth, async (req, res) => {
  try {
    const skill = await Skill.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json(skill);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to update"
    });
  }
});

// ============================================================
// PROJECTS
// ============================================================

app.get("/projects", async (req, res) => {
  try {
    const projects = await Project.find().sort({
      createdAt: -1
    });

    res.json(projects);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to fetch projects"
    });
  }
});

app.post(
  "/projects",
  auth,
  [
    body("t")
      .notEmpty()
      .trim()
      .isLength({ max: 120 }),

    body("u")
      .optional()
      .isURL()
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const {
        t,
        c,
        d,
        problem,
        result,
        s,
        img,
        u
      } = req.body;

      const project = await Project.create({
        t,
        c,
        d,
        problem,
        result,
        s,
        img: img || "",
        u
      });

      res.json({ project });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Failed to save project"
      });
    }
  }
);

app.delete("/projects/:id", auth, async (req, res) => {
  try {
    await Project.findByIdAndDelete(req.params.id);

    res.json({
      message: "Deleted ✅"
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to delete"
    });
  }
});

app.put("/projects/:id", auth, async (req, res) => {
  try {
    const project = await Project.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json(project);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to update"
    });
  }
});

// ============================================================
// MESSAGES
// ============================================================

app.post(
  "/messages",
  [
    body("name").trim().isLength({ max: 100 }),
    body("email").trim().toLowerCase().isEmail(),
    body("message")
      .notEmpty()
      .trim()
      .isLength({ max: 2000 })
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const {
        name,
        email,
        project_type,
        message
      } = req.body;

      await Message.create({
        name,
        email,
        project_type,
        message
      });

      res.json({
        message: "Message saved ✅"
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Failed to save message"
      });
    }
  }
);

app.get("/messages", auth, async (req, res) => {
  try {
    const messages = await Message.find().sort({
      createdAt: -1
    });

    res.json(messages);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to fetch messages"
    });
  }
});

// ============================================================
// ANALYTICS
// ============================================================

app.post("/analytics/hit", async (req, res) => {
  try {
    const today = new Date()
      .toISOString()
      .slice(0, 10);

    await Analytics.findOneAndUpdate(
      { date: today },
      {
        $inc: {
          visits: 1
        }
      },
      {
        upsert: true
      }
    );

    res.json({
      ok: true
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Analytics failed"
    });
  }
});

app.get("/analytics", auth, async (req, res) => {
  try {
    const today = new Date()
      .toISOString()
      .slice(0, 10);

    const weekStart = new Date();

    weekStart.setDate(
      weekStart.getDate() -
        weekStart.getDay() +
        1
    );

    const monthStart = new Date();
    monthStart.setDate(1);

    const fmt = (date) =>
      date.toISOString().slice(0, 10);

    const all = await Analytics.find();

    res.json({
      totalVisits: all.reduce(
        (sum, item) => sum + item.visits,
        0
      ),

      todayVisits:
        all.find((item) => item.date === today)?.visits || 0,

      thisWeek: all
        .filter(
          (item) =>
            item.date >= fmt(weekStart)
        )
        .reduce(
          (sum, item) =>
            sum + item.visits,
          0
        ),

      thisMonth: all
        .filter(
          (item) =>
            item.date >= fmt(monthStart)
        )
        .reduce(
          (sum, item) =>
            sum + item.visits,
          0
        )
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to fetch analytics"
    });
  }
});

// ============================================================
// ARTICLES
// ============================================================

app.get("/articles", async (req, res) => {
  try {
    const articles = await Article.find({
      published: true
    }).sort({
      createdAt: -1
    });

    res.json(articles);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to fetch articles"
    });
  }
});

app.post(
  "/articles",
  auth,
  [
    body("t")
      .notEmpty()
      .trim()
      .isLength({ max: 200 }),

    body("body")
      .notEmpty()
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const {
        t,
        c,
        r,
        e,
        body: content
      } = req.body;

      const article = await Article.create({
        t,
        c,
        r,
        e,
        body: content
      });

      res.json({ article });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Failed to create article"
      });
    }
  }
);

app.delete("/articles/:id", auth, async (req, res) => {
  try {
    await Article.findByIdAndDelete(req.params.id);

    res.json({
      message: "Deleted ✅"
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to delete"
    });
  }
});

app.put("/articles/:id", auth, async (req, res) => {
  try {
    const article = await Article.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json(article);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to update"
    });
  }
});

// ============================================================
// EXPORT FOR VERCEL
// ============================================================

module.exports = app;
