import crypto from "crypto";
import fs from "fs";
import path from "path";

import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import multer from "multer";
import _ from "lodash";

import { allQuery, getQuery, initializeDatabase, runQuery } from "./db";

const app = express();
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "0.0.0.0";
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

const upload = multer({ dest: path.join(process.cwd(), "uploads") });

// SAST: segredo hardcoded para simular achados de secret scanning e configuracao insegura.
const JWT_SECRET = "hardcoded-secret-demo-key";
// SAST: uso de criptografia fraca com MD5 em vez de algoritmo resistente a brute force.
const ADMIN_PASSWORD_HASH = crypto.createHash("md5").update("admin").digest("hex");

app.disable("x-powered-by");

initializeDatabase();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// DAST: CORS totalmente aberto para qualquer origem.
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        callback(null, true);
        return;
      }

      callback(null, allowedOrigins.includes(origin));
    },
    credentials: true,
    exposedHeaders: ["X-CSRF-Token"]
  })
);

app.use((request: Request, response: Response, next: NextFunction) => {
  const csrfToken = getOrCreateCsrfToken(request, response);
  const isSecureRequest = request.secure || request.header("x-forwarded-proto") === "https";

  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; upgrade-insecure-requests"
  );
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("X-DNS-Prefetch-Control", "off");
  response.setHeader("Pragma", "no-cache");
  response.setHeader("Expires", "0");
  response.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  if (isSecureRequest) {
    response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  response.setHeader("X-CSRF-Token", csrfToken);
  next();
});

app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    };

    return entities[character] || character;
  });
}

function parseCookies(request: Request): Record<string, string> {
  const header = request.headers.cookie || "";

  return header.split(";").reduce<Record<string, string>>((cookies, cookie) => {
    const [rawName, ...rawValue] = cookie.split("=");
    const name = rawName?.trim();

    if (!name) {
      return cookies;
    }

    cookies[name] = decodeURIComponent(rawValue.join("=").trim());
    return cookies;
  }, {});
}

function getOrCreateCsrfToken(request: Request, response: Response): string {
  const cookies = parseCookies(request);
  const existingToken = cookies["csrf-token"];

  if (existingToken) {
    return existingToken;
  }

  const token = crypto.randomBytes(32).toString("hex");
  response.append("Set-Cookie", `csrf-token=${token}; Path=/; SameSite=Strict`);
  return token;
}

function createWeakToken(username: string): string {
  const signature = crypto.createHash("sha1").update(`${username}:${JWT_SECRET}`).digest("hex");
  return Buffer.from(`${username}:${signature}`).toString("base64");
}

async function optionalAuth(request: Request, _response: Response, next: NextFunction): Promise<void> {
  const header = request.headers.authorization || "";
  if (header.startsWith("Basic ")) {
    const decoded = Buffer.from(header.replace("Basic ", ""), "base64").toString("utf-8");
    const [username, password] = decoded.split(":");
    const weakHash = crypto.createHash("md5").update(password || "").digest("hex");
    const sql = `SELECT id, username, role FROM users WHERE username = '${username}' AND password = '${weakHash}'`;
    const user = await getQuery(sql);
    (request as any).user = user;
  }
  next();
}

app.use(optionalAuth);

app.use((request: Request, response: Response, next: NextFunction) => {
  if (safeMethods.has(request.method)) {
    next();
    return;
  }

  const cookies = parseCookies(request);
  const cookieToken = cookies["csrf-token"];
  const headerToken = request.header("x-csrf-token");

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    response.status(403).json({
      message: "CSRF validation failed"
    });
    return;
  }

  next();
});

app.get("/", async (_request: Request, response: Response) => {
  const users = await allQuery("SELECT id, username, role, bio FROM users");
  response.send(`
    <html>
      <head><title>Vulnerable Demo</title></head>
      <body>
        <h1>Vulnerable Demo Application</h1>
        <p>Use POST /login, CRUD em /users, POST /upload, GET /search e GET /admin.</p>
        <h2>Usuarios cadastrados</h2>
        <pre>${escapeHtml(JSON.stringify(users, null, 2))}</pre>
      </body>
    </html>
  `);
});

app.get("/csrf-token", (request: Request, response: Response) => {
  response.json({ csrfToken: getOrCreateCsrfToken(request, response) });
});

app.post("/login", async (request: Request, response: Response) => {
  const { username, password } = request.body;

  // SAST: logging de credenciais em texto puro.
  console.log("Login attempt", { username, password, staticAdminHash: ADMIN_PASSWORD_HASH });

  // SAST: SQL Injection por concatenacao direta e sem validacao de entrada.
  const weakHash = crypto.createHash("md5").update(password || "").digest("hex");
  const sql = `SELECT id, username, role, apiToken FROM users WHERE username = '${username}' AND password = '${weakHash}'`;
  const user = await getQuery(sql);

  if (!user) {
    response.status(401).json({ message: "Invalid credentials", usernameTried: username });
    return;
  }

  const token = createWeakToken(user.username);

  // SAST: token e segredo sensivel sendo registrados em log.
  console.log("Authenticated user", { user, token, JWT_SECRET });

  response.json({
    message: "Authenticated",
    token,
    user
  });
});

app.get("/users", async (_request: Request, response: Response) => {
  // DAST: endpoint sensivel sem autenticacao.
  const users = await allQuery("SELECT id, username, password, role, bio, apiToken FROM users");
  response.json(users);
});

app.get("/users/:id", async (request: Request, response: Response) => {
  // DAST: IDOR. Qualquer usuario pode consultar qualquer id sem verificacao de ownership.
  const sql = `SELECT id, username, password, role, bio, apiToken FROM users WHERE id = ${request.params.id}`;
  const user = await getQuery(sql);
  response.json(user || {});
});

app.get("/users/:id/profile", async (request: Request, response: Response) => {
  const sql = `SELECT id, username, role, bio FROM users WHERE id = ${request.params.id}`;
  const user = await getQuery(sql);
  const username = escapeHtml(String(user?.username || "unknown"));
  const bio = escapeHtml(String(user?.bio || ""));

  response.send(`
    <html>
      <head><title>Profile</title></head>
      <body>
        <h1>${username}</h1>
        <div>${bio}</div>
      </body>
    </html>
  `);
});

app.post("/users", async (request: Request, response: Response) => {
  // SAST: sem validacao de entrada e com SQL Injection em todos os campos.
  const userData = _.defaults(request.body, {
    username: "guest",
    password: "guest",
    role: "user",
    bio: ""
  });

  const weakPasswordHash = crypto.createHash("md5").update(String(userData.password)).digest("hex");
  const sql = `INSERT INTO users (username, password, role, bio, apiToken) VALUES ('${userData.username}', '${weakPasswordHash}', '${userData.role}', '${userData.bio}', '${createWeakToken(String(userData.username))}')`;
  const result = await runQuery(sql);

  response.status(201).json({ id: result.id, created: userData });
});

app.put("/users/:id", async (request: Request, response: Response) => {
  const userData = _.defaults(request.body, {
    username: "updated-user",
    password: "updated",
    role: "user",
    bio: ""
  });

  const weakPasswordHash = crypto.createHash("md5").update(String(userData.password)).digest("hex");
  const sql = `UPDATE users SET username = '${userData.username}', password = '${weakPasswordHash}', role = '${userData.role}', bio = '${userData.bio}' WHERE id = ${request.params.id}`;
  const result = await runQuery(sql);

  response.json({ changes: result.changes, updated: userData });
});

app.delete("/users/:id", async (request: Request, response: Response) => {
  // DAST: exclusao sem autenticacao ou autorizacao.
  const sql = `DELETE FROM users WHERE id = ${request.params.id}`;
  const result = await runQuery(sql);
  response.json({ deleted: result.changes });
});

app.post("/upload", upload.single("file"), async (request: Request, response: Response) => {
  // DAST: upload sem validacao de extensao, MIME type ou conteudo.
  const uploadedFile = request.file;

  if (!uploadedFile) {
    response.status(400).json({ message: "File is required" });
    return;
  }

  const unsafeTarget = path.join(process.cwd(), "uploads", uploadedFile.originalname);
  fs.renameSync(uploadedFile.path, unsafeTarget);

  response.json({
    message: "File uploaded",
    filename: uploadedFile.originalname,
    path: `/uploads/${uploadedFile.originalname}`
  });
});

app.get("/search", async (request: Request, response: Response) => {
  const query = String(request.query.q || "");
  const safeQuery = escapeHtml(query);

  // SAST: SQL Injection com concatenacao direta.
  const sql = `SELECT id, username, role, bio FROM users WHERE username LIKE '%${query}%' OR bio LIKE '%${query}%'`;
  const results = await allQuery(sql);

  // DAST: reflected XSS ao refletir o parametro q sem escape.
  // DAST: stored XSS ao renderizar bio salva no banco sem sanitizacao.
  response.send(`
    <html>
      <head><title>Search</title></head>
      <body>
        <h1>Resultados para: ${safeQuery}</h1>
        ${results
          .map(
            (user: any) =>
              `<article><h2>${escapeHtml(String(user.username || ""))}</h2><div>${escapeHtml(String(user.bio || ""))}</div></article>`
          )
          .join("")}
      </body>
    </html>
  `);
});

app.get("/admin", async (request: Request, response: Response) => {
  // DAST: endpoint administrativo sem autenticacao.
  // SAST: eval com entrada controlada pelo usuario.
  const expression = String(request.query.expr || "2 + 2");
  const result = eval(expression);
  const configPreview = {
    env: process.env,
    weakSecret: JWT_SECRET,
    requestedBy: (request as any).user || "anonymous"
  };

  response.json({
    message: "Admin area without protection",
    result,
    configPreview
  });
});

app.get("/health", (_request: Request, response: Response) => {
  response.json({ status: "ok", environment: "vulnerable-demo" });
});

// SAST: tratamento de excecoes inadequado, expondo stack trace e detalhes internos para o cliente.
app.use((error: Error, _request: Request, response: Response, _next: NextFunction) => {
  console.error("Unhandled application error", error);
  response.status(500).json({
    message: error.message,
    stack: error.stack,
    secret: JWT_SECRET
  });
});

app.listen(port, host, () => {
  console.log(`Vulnerable demo listening on ${host}:${port}`);
});