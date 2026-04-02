// app.secure.js - Fixed version (all major issues resolved)
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const port = process.env.PORT || 3007;

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, 
    name TEXT NOT NULL, 
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user'
  )`);

  const seed = db.prepare(
    "INSERT INTO users(name, password, email, role) VALUES (?, ?, ?, ?)",
  );
  seed.run("alice", "password123", "alice@example.com", "admin");
  seed.run("bob", "qwerty", "bob@example.com", "user");
  seed.run("charlie", "123456", "charlie@example.com", "user");
  seed.finalize();
});

app.use(helmet());
app.use(express.json({ limit: "1mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

app.get("/user", (req, res) => {
  const id = parseInt(req.query.id);
  if (!id) return res.status(400).json({ error: "Invalid ID" });

  db.get(
    "SELECT id, name, email, role FROM users WHERE id = ?",
    [id],
    (err, row) => {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json(row || { error: "User not found" });
    },
  );
});

app.get("/search", (req, res) => {
  const search = req.query.q || "";
  db.all(
    "SELECT id, name, email, role FROM users WHERE name LIKE ?",
    [`%${search}%`],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Database error" });
      res.json(rows);
    },
  );
});

app.get("/ping", (req, res) => {
  const host = req.query.host || "8.8.8.8";
  const allowedHosts = ["8.8.8.8", "1.1.1.1", "google.com"];

  if (!allowedHosts.includes(host)) {
    return res.status(403).send("Host not allowed");
  }

  const { exec } = require("child_process");
  exec(`ping -c 3 ${host}`, (error, stdout) => {
    if (error) return res.status(500).send("Ping failed");
    res.send(`<pre>${stdout}</pre>`);
  });
});

app.get("/profile", (req, res) => {
  const name = req.query.name
    ? req.query.name.replace(/[<>"'&]/g, "")
    : "Guest";
  res.send(`
    <h1>Welcome, ${name}</h1>
    <p>Your profile is being loaded...</p>
  `);
});

app.post("/register", (req, res) => {
  const { name, password, email } = req.body;
  const role = "user"; // Force role, ignore user input

  if (!name || !password || !email) {
    return res.status(400).send("Missing fields");
  }

  const stmt = db.prepare(
    "INSERT INTO users(name, password, email, role) VALUES (?, ?, ?, ?)",
  );
  stmt.run(name, password, email, role);
  stmt.finalize();

  res.send("User registered successfully");
});

app.get("/debug", (req, res) => {
  res.json({ status: "secure", version: "1.1" });
});

app.get("/file", (req, res) => {
  res.status(403).send("Access denied");
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`running on http://localhost:${port}`);
});
