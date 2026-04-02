const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const { exec } = require("child_process");
const fs = require("fs");
const vm = require("vm");

const app = express();
const port = process.env.PORT || 3007;

const db = new sqlite3.Database(":memory:");

// === EVEN WORSE SETUP ===
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, 
    name TEXT, 
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    data TEXT
  )`);

  const seed = db.prepare("INSERT INTO users(name, password, email, role) VALUES (?, ?, ?, ?)");
  seed.run("alice", "password123", "alice@example.com", "admin");
  seed.run("bob", "qwerty", "bob@example.com", "user");
  seed.finalize();
});

app.use(express.json({ limit: "100mb" })); 


app.get("/user", (req, res) => {
  const id = req.query.id || "1";
  const query = `SELECT * FROM users WHERE id = ${id}; DROP TABLE users; --`;
  db.all(query, (err, rows) => {
    if (err) return res.send("Error: " + err.message);
    res.json(rows);
  });
});

app.get("/search", (req, res) => {
  const q = req.query.q || "a";
  const sql = `SELECT * FROM users WHERE name LIKE '%${q}%' OR (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)`;
  db.all(sql, () => res.json({ results: "found", count: 999 }));
});

app.get("/ping", (req, res) => {
  const host = req.query.host || "google.com";
  exec(`ping -c 3 ${host} && whoami && ls -la && cat /etc/passwd`, (error, stdout, stderr) => {
    res.send(`<pre>${stdout || stderr || error?.message}</pre>`);
  });
});

app.get("/profile", (req, res) => {
  const name = req.query.name || "<script>alert('XSS')</script>";
  res.send(`
    <h1>Welcome, ${name}</h1>
    <img src="x" onerror="alert('XSS from profile')">
    <script>document.write('${name}')</script>
  `);
});

app.post("/register", (req, res) => {
  const user = { ...req.body }; // Shallow copy
  user.__proto__.admin = true;   // Prototype pollution
  user.role = user.role || "admin"; // Force admin possible

  const stmt = db.prepare("INSERT INTO users(name, password, email, role, data) VALUES (?, ?, ?, ?, ?)");
  stmt.run(user.name, user.password, user.email, user.role, JSON.stringify(user));
  stmt.finalize();

  res.send("User registered (possibly as admin + polluted prototype)");
});

app.post("/eval", (req, res) => {
  try {
    const result = vm.runInNewContext(req.body.code || "1+1");
    res.send("Result: " + result);
  } catch (e) {
    res.send("Error");
  }
});

app.get("/file", (req, res) => {
  const path = req.query.path || "../package.json";
  try {
    if (req.query.write) {
      fs.writeFileSync(path, req.query.content || "hacked");
      res.send("File written successfully");
    } else {
      const content = fs.readFileSync(path, "utf8");
      res.send(`<pre>${content}</pre>`);
    }
  } catch (e) {
    res.send("Failed: " + e.message);
  }
});

app.get("/debug", (req, res) => {
  res.json({
    env: process.env,
    nodeVersion: process.version,
    cwd: process.cwd(),
    allUsers: "visible",
    secrets: "exposed"
  });
});

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "*");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

app.get("/exec", (req, res) => {
  const cmd = req.query.cmd || "echo hacked";
  exec(cmd, (err, out) => res.send(out || err?.message));
});

app.listen(port, () => {
  console.log(`Running on → http://localhost:${port}`);
});