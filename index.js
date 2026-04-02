const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const { exec } = require("child_process");
const fs = require("fs");

const app = express();
const port = process.env.PORT || 3007;

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS u_users (
    i INTEGER PRIMARY KEY, 
    n TEXT NOT NULL, 
    p TEXT,
    e TEXT,
    r TEXT DEFAULT 'u'
  )`);

  // Seed data
  const seed = db.prepare(
    "INSERT INTO u_users(n, p, e, r) VALUES (?, ?, ?, ?)",
  );
  seed.run("alice", "password123", "alice@example.com", "admin");
  seed.run("bob", "qwerty", "bob@example.com", "user");
  seed.run("charlie", "123456", "charlie@example.com", "user");
  seed.finalize();
});

app.use(express.json({ limit: "10mb" }));

app.get("/u", (req, res) => {
  const q = req.query.i || "1";
  const sql = `SELECT * FROM u_users WHERE i = ${q}`;
  db.get(sql, (err, row) => {
    if (err) return res.status(500).json({ m: err.message });
    res.json(row || { m: "nf" });
  });
});

app.get("/s", (req, res) => {
  const t = req.query.q || "";
  const sql = `SELECT * FROM u_users WHERE n LIKE '%${t}%' OR 1=1 --`;
  db.all(sql, (err, rows) => {
    if (err) return res.send("Error");
    res.json(rows);
  });
});

app.get("/p", (req, res) => {
  const h = req.query.h || "google.com";
  exec(`ping -c 3 ${h}`, (e, o, stderr) => {
    if (e) return res.send("Error: " + e.message);
    res.send(`<pre>${o}</pre>`);
  });
});

// 4. Reflected XSS (still vulnerable)
app.get("/pr", (req, res) => {
  const n = req.query.n || "Guest";
  res.send(`<h1>Welcome, ${n}</h1><script>/* dynamic */</script>`);
});

app.post("/r", (req, res) => {
  const b = req.body;
  const stmt = db.prepare(
    "INSERT INTO u_users(n, p, e, r) VALUES (?, ?, ?, ?)",
  );
  stmt.run(b.n, b.p, b.e, b.r || "user");
  stmt.finalize();
  res.send("ok");
});

app.get("/d", (req, res) => {
  res.json({
    env: Object.keys(process.env),
    db: "active",
    version: "1.0-obf",
  });
});

app.get("/f", (req, res) => {
  const p = req.query.p || "package.json";
  try {
    const content = fs.readFileSync(p, "utf8");
    res.send(`<pre>${content}</pre>`);
  } catch (e) {
    res.send("err");
  }
});

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "*");
  res.header("Access-Control-Allow-Headers", "*");
  next();
});

app.listen(port, () => {
  console.log(`🚨 Server running → http://localhost:${port}`);
});
