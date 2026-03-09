const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

console.log("✅ RUNNING SERVER VERSION: FULL V7 (AUTHENTICATOR + USERS + EXPANDED RECORDS)");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ================= HELPERS =================

function cleanEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeRole(role) {
  const r = String(role || "").trim().toLowerCase();

  if (r === "admin") return "admin";
  if (r === "state" || r === "state_officer") return "state_officer";
  if (r === "lga" || r === "lga_officer") return "lga_officer";

  return r;
}

function requireFields(obj, fields) {
  return fields.filter((f) => !obj[f] || String(obj[f]).trim() === "");
}

async function logAudit({ userId, action, recordId, oldData, newData }) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, record_id, old_data, new_data)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb)`,
      [
        userId || null,
        action,
        recordId || null,
        oldData ? JSON.stringify(oldData) : null,
        newData ? JSON.stringify(newData) : null,
      ]
    );
  } catch (err) {
    console.error("Audit failed:", err.message);
  }
}

// ================= AUTH =================

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized. Please login." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ message: "Unauthorized. Please login." });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden. Admin only." });
  }
  next();
}

// ================= DEFAULT ADMIN =================

async function ensureAdminUser() {
  const email = cleanEmail(process.env.ADMIN_EMAIL);
  const password = String(process.env.ADMIN_PASSWORD || "").trim();
  const name = process.env.ADMIN_NAME || "Admin User";

  if (!email || !password) {
    console.log("⚠️ ADMIN_EMAIL / ADMIN_PASSWORD not set in .env (skipping admin auto-create)");
    return;
  }

  const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (exists.rows.length) return;

  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    `INSERT INTO users (full_name, email, password_hash, role)
     VALUES ($1,$2,$3,'admin')`,
    [name, email, hash]
  );

  console.log("✅ Default admin created");
}

// ================= PAGES =================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/authenticator", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "authenticator.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/users", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "users.html"));
});

app.get("/index.html", (req, res) => res.redirect("/"));
app.get("/login.html", (req, res) => res.redirect("/login"));
app.get("/authenticator.html", (req, res) => res.redirect("/authenticator"));
app.get("/dashboard.html", (req, res) => res.redirect("/dashboard"));
app.get("/users.html", (req, res) => res.redirect("/users"));

// ================= LOGIN =================

app.post("/api/login", async (req, res) => {
  try {
    const email = cleanEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const result = await pool.query(
      "SELECT id, email, password_hash, role FROM users WHERE email=$1",
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    return res.json({ token, role: user.role });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// =======================================================
// RECORDS (AUTH REQUIRED)
// =======================================================

app.get("/api/records", requireAuth, async (req, res) => {
  try {
    const { state, lga, page = "1", limit = "50" } = req.query;

    const pageNum = Math.max(parseInt(page, 10) || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
    const offset = (pageNum - 1) * limitNum;

    const where = [];
    const values = [];
    let i = 1;

    if (state && state.trim()) {
      where.push(`LOWER(state) = LOWER($${i++})`);
      values.push(state.trim());
    }

    if (lga && lga.trim()) {
      where.push(`LOWER(lga) = LOWER($${i++})`);
      values.push(lga.trim());
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const countRes = await pool.query(
      `SELECT COUNT(*)::int AS total FROM records ${whereSql}`,
      values
    );

    values.push(limitNum, offset);

    const dataRes = await pool.query(
      `SELECT id,
              full_name AS name,
              phone,
              state,
              lga,
              ward,
              polling_unit,
              pvc_vin,
              position,
              age,
              gender,
              support_group
       FROM records
       ${whereSql}
       ORDER BY id DESC
       LIMIT $${i++} OFFSET $${i++}`,
      values
    );

    return res.json({
      total: countRes.rows[0].total,
      page: pageNum,
      limit: limitNum,
      data: dataRes.rows,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/records", requireAuth, async (req, res) => {
  try {
    const payload = req.body || {};

    const full_name = (payload.full_name || payload.name || "").trim();
    const phone = (payload.phone || "").trim();
    const state = (payload.state || "").trim();
    const lga = (payload.lga || "").trim();
    const ward = (payload.ward || "").trim();
    const polling_unit = (payload.polling_unit || "").trim();
    const pvc_vin = (payload.pvc_vin || "").trim();
    const position = (payload.position || "").trim();
    const age = payload.age ? String(payload.age).trim() : "";
    const gender = (payload.gender || "").trim();
    const support_group = (payload.support_group || "").trim();

    const missing = requireFields(
      { full_name, phone, state, lga, ward },
      ["full_name", "phone", "state", "lga", "ward"]
    );

    if (missing.length) {
      return res.status(400).json({ message: `Missing fields: ${missing.join(", ")}` });
    }

    const created = await pool.query(
      `INSERT INTO records (
        full_name,
        phone,
        state,
        lga,
        ward,
        polling_unit,
        pvc_vin,
        position,
        age,
        gender,
        support_group
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING id, full_name, phone, state, lga, ward, polling_unit, pvc_vin, position, age, gender, support_group`,
      [full_name, phone, state, lga, ward, polling_unit, pvc_vin, position, age, gender, support_group]
    );

    await logAudit({
      userId: req.user?.id,
      action: "CREATE_RECORD",
      recordId: created.rows[0].id,
      oldData: null,
      newData: created.rows[0],
    });

    return res.status(201).json({ message: "Record created", data: created.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/records/:id", requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ message: "Invalid record id" });

    const oldRes = await pool.query(
      `SELECT id, full_name, phone, state, lga, ward, polling_unit, pvc_vin, position, age, gender, support_group
       FROM records WHERE id=$1`,
      [id]
    );

    if (!oldRes.rows.length) return res.status(404).json({ message: "Record not found" });

    const oldRecord = oldRes.rows[0];
    const payload = req.body || {};

    const full_name = (payload.full_name || payload.name || oldRecord.full_name || "").trim();
    const phone = (payload.phone || oldRecord.phone || "").trim();
    const state = (payload.state || oldRecord.state || "").trim();
    const lga = (payload.lga || oldRecord.lga || "").trim();
    const ward = (payload.ward || oldRecord.ward || "").trim();
    const polling_unit = (payload.polling_unit || oldRecord.polling_unit || "").trim();
    const pvc_vin = (payload.pvc_vin || oldRecord.pvc_vin || "").trim();
    const position = (payload.position || oldRecord.position || "").trim();
    const age = payload.age !== undefined && payload.age !== null && String(payload.age).trim() !== ""
      ? String(payload.age).trim()
      : (oldRecord.age || "");
    const gender = (payload.gender || oldRecord.gender || "").trim();
    const support_group = (payload.support_group || oldRecord.support_group || "").trim();

    const missing = requireFields(
      { full_name, phone, state, lga, ward },
      ["full_name", "phone", "state", "lga", "ward"]
    );

    if (missing.length) {
      return res.status(400).json({ message: `Missing fields: ${missing.join(", ")}` });
    }

    const updatedRes = await pool.query(
      `UPDATE records
       SET full_name=$1,
           phone=$2,
           state=$3,
           lga=$4,
           ward=$5,
           polling_unit=$6,
           pvc_vin=$7,
           position=$8,
           age=$9,
           gender=$10,
           support_group=$11,
           updated_at=NOW()
       WHERE id=$12
       RETURNING id, full_name, phone, state, lga, ward, polling_unit, pvc_vin, position, age, gender, support_group`,
      [full_name, phone, state, lga, ward, polling_unit, pvc_vin, position, age, gender, support_group, id]
    );

    await logAudit({
      userId: req.user?.id,
      action: "UPDATE_RECORD",
      recordId: id,
      oldData: oldRecord,
      newData: updatedRes.rows[0],
    });

    return res.json({ message: "Record updated", data: updatedRes.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/records/:id", requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ message: "Invalid record id" });

    const oldRes = await pool.query(
      `SELECT id, full_name, phone, state, lga, ward, polling_unit, pvc_vin, position, age, gender, support_group
       FROM records WHERE id=$1`,
      [id]
    );

    if (!oldRes.rows.length) return res.status(404).json({ message: "Record not found" });

    const oldRecord = oldRes.rows[0];

    await pool.query(`DELETE FROM records WHERE id=$1`, [id]);

    await logAudit({
      userId: req.user?.id,
      action: "DELETE_RECORD",
      recordId: id,
      oldData: oldRecord,
      newData: null,
    });

    return res.json({ message: "Record deleted" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// =======================================================
// USERS (ADMIN ONLY)
// =======================================================

const ALLOWED_ROLES = ["admin", "state_officer", "lga_officer"];

app.get("/api/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, role, created_at
       FROM users
       ORDER BY id DESC`
    );
    return res.json({ data: result.rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const full_name = String(req.body?.full_name || "").trim();
    const email = cleanEmail(req.body?.email);
    const password = String(req.body?.password || "").trim();
    const role = normalizeRole(req.body?.role || "lga_officer");

    if (!full_name || !email || !password) {
      return res.status(400).json({ message: "All fields required." });
    }

    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({
        message: "Invalid role. Use admin/state_officer/lga_officer",
      });
    }

    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (exists.rows.length) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    const created = await pool.query(
      `INSERT INTO users (full_name, email, password_hash, role)
       VALUES ($1,$2,$3,$4)
       RETURNING id, full_name, email, role, created_at`,
      [full_name, email, hash, role]
    );

    await logAudit({
      userId: req.user?.id,
      action: "CREATE_USER",
      recordId: null,
      oldData: null,
      newData: created.rows[0],
    });

    return res.status(201).json({ message: "User created", data: created.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/users/:id/password", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const password = String(req.body?.password || "").trim();

    if (!id) return res.status(400).json({ message: "Invalid user id" });
    if (!password) return res.status(400).json({ message: "Password required" });

    const oldRes = await pool.query(
      `SELECT id, full_name, email, role FROM users WHERE id=$1`,
      [id]
    );
    if (!oldRes.rows.length) return res.status(404).json({ message: "User not found" });

    const hash = await bcrypt.hash(password, 10);

    const updated = await pool.query(
      `UPDATE users SET password_hash=$1 WHERE id=$2
       RETURNING id, full_name, email, role`,
      [hash, id]
    );

    await logAudit({
      userId: req.user?.id,
      action: "RESET_PASSWORD",
      recordId: null,
      oldData: oldRes.rows[0],
      newData: updated.rows[0],
    });

    return res.json({ message: "Password reset", data: updated.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ message: "Invalid user id" });

    if (req.user?.id === id) {
      return res.status(400).json({ message: "You can’t delete your own account." });
    }

    const oldRes = await pool.query(
      `SELECT id, full_name, email, role FROM users WHERE id=$1`,
      [id]
    );
    if (!oldRes.rows.length) return res.status(404).json({ message: "User not found" });

    await pool.query(`DELETE FROM users WHERE id=$1`, [id]);

    await logAudit({
      userId: req.user?.id,
      action: "DELETE_USER",
      recordId: null,
      oldData: oldRes.rows[0],
      newData: null,
    });

    return res.json({ message: "User deleted" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ================= START =================

app.listen(PORT, async () => {
  try {
    await ensureAdminUser();
    console.log(`Server running on port ${PORT}`);
  } catch (err) {
    console.error("Startup error:", err);
  }
});