# Ambiente Web Vulneravel para SAST, DAST e SCA

Este projeto e propositalmente vulneravel e existe apenas para fins educacionais, laboratorios internos e validacao de ferramentas de seguranca como SonarQube, Checkmarx, OWASP ZAP, Burp Suite, Snyk e Dependabot.

## Stack escolhida

- Node.js
- TypeScript
- Express
- SQLite
- Docker / Docker Compose

## Como executar

### Localmente

```bash
npm install
set APP_ORIGIN=http://localhost:3000
set CSRF_TOKEN=change-me-csrf-token
npm run dev
```

Aplicacao em `http://localhost:3000`.

### Com Docker

```bash
docker compose up --build
```

O banco SQLite fica em `./data/vulnerable.sqlite` e os uploads em `./uploads`.

## Observacoes desta branch

- As respostas agora enviam headers de hardening como `Content-Security-Policy`, `X-Frame-Options` e `X-Content-Type-Options`.
- Requisicoes `POST`, `PUT` e `DELETE` exigem o header `X-CSRF-Token` com o mesmo valor de `CSRF_TOKEN`.
- A origem permitida por CORS e pela validacao de origem e controlada por `APP_ORIGIN`.

## Endpoints principais

- `POST /login`
- `GET /users`
- `GET /users/:id`
- `POST /users`
- `PUT /users/:id`
- `DELETE /users/:id`
- `POST /upload`
- `GET /search?q=texto`
- `GET /admin?expr=2+2`

## Credenciais iniciais

- usuario: `admin`
- senha: `admin`

## Vulnerabilidades intencionais

### SAST

- SQL Injection por concatenacao direta em consultas SQLite.
- Secrets hardcoded no codigo (`JWT_SECRET`, tokens estaticos e hashes seedados).
- Criptografia fraca com MD5 e SHA1.
- Falta de validacao de entrada em CRUD, login, busca e upload.
- Uso de `eval()` no endpoint `/admin`.
- Tratamento de excecao inadequado expondo stack trace e segredo interno.
- Logging de dados sensiveis em `/login`.

### DAST

- XSS refletido em `/search`.
- XSS armazenado ao persistir `bio` e renderizar sem sanitizacao.
- Falta de autenticacao em `/users`, `/admin` e exclusao de usuarios.
- IDOR em `GET /users/:id` e `GET /users/:id/profile`.
- Ausencia de rate limiting para brute force em `/login`.
- Headers inseguros sem CSP, HSTS e outros controles.
- Upload de arquivos sem validacao.
- CORS aberto com `*`.

### SCA

Dependencias antigas e propositalmente vulneraveis foram fixadas em [package.json](package.json):

- `express@4.16.4`
- `axios@0.21.1`
- `lodash@4.17.11`
- `multer@1.4.2`

## Observacoes para teste

- O endpoint `/search` pode ser usado para validar SQL Injection e XSS ao mesmo tempo.
- O campo `bio` dos usuarios permite armazenar payloads HTML/JavaScript.
- O endpoint `/admin` executa expressoes enviadas por query string.
- O login nao possui rate limiting ou MFA.

## Aviso

Nao utilize este projeto em ambientes expostos ou produtivos. As falhas foram mantidas de forma intencional e nao devem ser corrigidas neste laboratorio.