const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const path = require("path");
const fs = require("fs");



const app = express();
const upload = multer({ dest: "uploads/" });

// Configuração básica
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// "Segredo" hardcoded (intencionalmente errado)
const JWT_SECRET = "super_secret_key_123";
const ADMIN_TOKEN = "admin-token-123"; // usado em /admin (horrível de propósito)

// Banco SQLite em memória (com SQL Injection de propósito)
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      password TEXT,
      isAdmin INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      description TEXT,
      price REAL
    )
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message TEXT,
      createdAt TEXT
    )
  `);

  // Usuário admin default com senha fraca
  db.run(
    `INSERT INTO users (email, password, isAdmin) VALUES ('admin@insecure.local', '123456', 1)`
  );
  db.run(
    `INSERT INTO users (email, password, isAdmin) VALUES ('user@insecure.local', 'password', 0)`
  );

  // Produtos de teste
  db.run(
    `INSERT INTO products (name, description, price) VALUES
      ('Vuln Juice', 'Reflected XSS friendly <script>alert(1)</script>', 9.99),
      ('SQLi Soda', 'Test SQL injections using the search endpoint', 4.20),
      ('Leak Latte', 'Hardcoded secrets and verbose errors inside', 7.77)
    `
  );
});

// Home simples
app.get("/", (req, res) => {
  res.send(`
    <h1>Insecure Test Shop</h1>
    <p>App intencionalmente vulnerável para testes de segurança.</p>
    <ul>
      <li><a href="/products">/products</a></li>
      <li><a href="/search?q=test">/search?q=teste</a> (XSS / SQLi-like)</li>
      <li><a href="/login-demo">/login-demo</a></li>
      <li><a href="/feedback">/feedback</a></li>
      <li><a href="/admin">/admin</a></li>
      <li><a href="/upload">/upload</a></li>
    </ul>
  `);
});

// Lista de produtos (OK, mas sem autenticação)
app.get("/products", (req, res) => {
  db.all("SELECT id, name, description, price FROM products", (err, rows) => {
    if (err) {
      return res.status(500).send("Erro ao listar produtos");
    }
    res.json(rows);
  });
});

// Endpoint vulnerável a Reflected XSS e pseudo-SQLi
app.get("/search", (req, res) => {
  const q = req.query.q || "";

  // Intencionalmente construindo query sem bind (SQL Injection)
  const sql = `SELECT id, name, description, price FROM products
               WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;

  db.all(sql, (err, rows) => {
    if (err) {
      // Exposição de erro interno
      return res.status(500).send("Erro na query: " + err.message);
    }

    // Reflected XSS: devolve diretamente o parâmetro sem sanitização
    let html = `<h1>Resultados para: ${q}</h1><ul>`;
    rows.forEach((p) => {
      html += `<li>${p.name} - ${p.description} - $${p.price}</li>`;
    });
    html += `</ul><a href="/">Voltar</a>`;

    res.send(html);
  });
});

// Form de login demo
app.get("/login-demo", (req, res) => {
  res.send(`
    <h1>Login Inseguro</h1>
    <form method="POST" action="/login">
      <input name="email" placeholder="email" />
      <input name="password" type="password" placeholder="senha" />
      <button type="submit">Entrar</button>
    </form>
  `);
});

// Login vulnerável: sem hash, sem bloqueio, mensagem muito detalhada
app.post("/login", (req, res) => {
  const { email, password } = req.body || {};
  const sql = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;

  db.get(sql, (err, user) => {
    if (err) {
      return res.status(500).send("Erro no login: " + err.message);
    }
    if (!user) {
      return res.status(401).send("Credenciais inválidas (debug: user não encontrado)");
    }
    // "Token" inseguro
    const fakeToken = Buffer.from(`${email}:${JWT_SECRET}`).toString("base64");
    res.send(`
      <p>Login OK para ${email}</p>
      <p>Seu token (falso e inseguro): ${fakeToken}</p>
      <p>isAdmin: ${user.isAdmin}</p>
      <a href="/">Home</a>
    `);
  });
});

// Área admin insegura: "autenticação" via query string com token fixo
app.get("/admin", (req, res) => {
  const token = req.query.token;

  if (token !== ADMIN_TOKEN) {
    return res.status(401).send(`
      <h1>Acesso negado</h1>
      <p>Passe ?token=${ADMIN_TOKEN} para entrar (intencionalmente ridículo).</p>
    `);
  }

  db.all("SELECT id, email, password, isAdmin FROM users", (err, users) => {
    if (err) {
      return res.status(500).send("Erro: " + err.message);
    }
    res.send(`
      <h1>Admin Panel</h1>
      <pre>${JSON.stringify(users, null, 2)}</pre>
      <p>Segredos e senhas em claro expostos.</p>
      <a href="/">Home</a>
    `);
  });
});

// Feedback com Stored XSS (nada de sanitização)
app.get("/feedback", (req, res) => {
  db.all("SELECT message, createdAt FROM feedback ORDER BY id DESC", (err, rows) => {
    if (err) {
      return res.status(500).send("Erro ao carregar feedback");
    }
    let html = `
      <h1>Feedback</h1>
      <form method="POST" action="/feedback">
        <textarea name="message" placeholder="Envie HTML/JS se quiser"></textarea>
        <button type="submit">Enviar</button>
      </form>
      <h2>Mensagens</h2>
      <ul>
    `;
    rows.forEach((f) => {
      // Stored XSS aqui
      html += `<li>${f.message} - ${f.createdAt}</li>`;
    });
    html += `</ul><a href="/">Home</a>`;
    res.send(html);
  });
});

app.post("/feedback", (req, res) => {
  const msg = req.body.message || "";
  const now = new Date().toISOString();
  // sem validação
  db.run(
    `INSERT INTO feedback (message, createdAt) VALUES ('${msg}', '${now}')`,
    (err) => {
      if (err) {
        return res.status(500).send("Erro ao salvar feedback: " + err.message);
      }
      res.redirect("/feedback");
    }
  );
});

// Upload inseguro
app.get("/upload", (req, res) => {
  res.send(`
    <h1>Upload Inseguro</h1>
    <form method="POST" action="/upload" enctype="multipart/form-data">
      <input type="file" name="file"/>
      <button type="submit">Enviar</button>
    </form>
    <a href="/">Home</a>
  `);
});

// Aceita qualquer arquivo, sem validação, expõe caminho
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("Nenhum arquivo enviado");
  }

  const info = {
    originalName: req.file.originalname,
    storedAs: req.file.filename,
    path: path.join(__dirname, req.file.path),
  };

  res.send(`
    <h1>Upload recebido</h1>
    <pre>${JSON.stringify(info, null, 2)}</pre>
    <p>Arquivo armazenado em pasta acessível no servidor. Sem validação de tipo, tamanho, ou extensão.</p>
    <a href="/">Home</a>
  `);
});

// Exposição de arquivos enviados (potencial LFI/RFI se estender)
app.get("/uploads/:file", (req, res) => {
  const filePath = path.join(__dirname, "uploads", req.params.file);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send("Arquivo não encontrado");
  }
  res.sendFile(filePath);
});

// Start
const port = 3000;
app.listen(port, () => {
  console.log(`Insecure Test Shop rodando em http://localhost:${port}`);
});
