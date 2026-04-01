const express = require("express");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const port = process.env.PORT || 3000;

const db = new sqlite3.Database(":memory:");

// === SUPER INSECURE SETUP ===
db.serialize(() => {
  // No input sanitization, dangerous table creation
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, 
    name TEXT NOT NULL, 
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user'
  )`);

  const seed = db.prepare("INSERT INTO users(name, password, email, role) VALUES (?, ?, ?, ?)");
  
  seed.run("alice", "password123", "alice@example.com", "admin");
  seed.run("bob", "qwerty", "bob@example.com", "user");
  seed.run("charlie", "123456", "charlie@example.com", "user");
  seed.finalize();
});

app.use(express.json()); // No size limit = DoS possible

// === CRITICAL VULNERABILITIES ===

// 1. SQL Injection (Classic)
app.get("/user", (req, res) => {
  const id = req.query.id;

  // Direct string concatenation → SQL Injection
  const query = `SELECT id, name, password, email, role FROM users WHERE id = ${id}`;

  db.get(query, (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(row || { error: "User not found" });
  });
});

// 2. Even worse - Universal SQL Injection endpoint
app.get("/search", (req, res) => {
  const search = req.query.q || "";
  
  // Blind SQLi + Information Disclosure
  const sql = `SELECT * FROM users WHERE name LIKE '%${search}%' OR 1=1 --`;
  
  db.all(sql, (err, rows) => {
    if (err) return res.send("Error: " + err.message);
    res.json(rows);
  });
});

// 3. Command Injection
app.get("/ping", (req, res) => {
  const host = req.query.host || "google.com";
  
  // Extremely dangerous - child_process without sanitization
  const { exec } = require("child_process");
  exec(`ping -c 3 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.send("Error: " + error.message);
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// 4. XSS + No Security Headers
app.get("/profile", (req, res) => {
  const name = req.query.name || "Guest";
  
  // Reflected XSS
  res.send(`
    <h1>Welcome, ${name}</h1>
    <p>Your profile is being loaded...</p>
    <script>alert('XSS if name contains payload')</script>
  `);
});

// 5. Mass Assignment + No Validation
app.post("/register", (req, res) => {
  const { name, password, email, role } = req.body;

  // Allows attacker to set role=admin
  const stmt = db.prepare("INSERT INTO users(name, password, email, role) VALUES (?, ?, ?, ?)");
  stmt.run(name, password, email, role || "user");  // role from user input!
  stmt.finalize();

  res.send("User registered successfully (maybe as admin?)");
});

// 6. No Rate Limiting + Debug Info
app.get("/debug", (req, res) => {
  res.json({
    environment: process.env,
    database: "In-memory SQLite",
    users: "All users visible",
    version: "Super Insecure v1.0"
  });
});

// 7. Arbitrary File Read (Path Traversal)
app.get("/file", (req, res) => {
  const fs = require("fs");
  const filepath = req.query.path || "package.json";
  
  try {
    const content = fs.readFileSync(filepath, "utf8");
    res.send(`<pre>${content}</pre>`);
  } catch (e) {
    res.send("File not found or access denied");
  }
});

// 8. Weak CORS + No Helmet
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "*");
  res.header("Access-Control-Allow-Headers", "*");
  next();
});

app.listen(port, () => {
  console.log(`🚨  http://localhost:${port}`);
});