import path from "path";
import sqlite3 from "sqlite3";

const databasePath = path.join(process.cwd(), "data", "vulnerable.sqlite");

sqlite3.verbose();

export const db = new sqlite3.Database(databasePath);

export function initializeDatabase(): void {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        bio TEXT DEFAULT '',
        apiToken TEXT DEFAULT ''
      )
    `);

    db.get("SELECT id FROM users WHERE username = 'admin'", (error, row) => {
      if (error) {
        console.error("Database setup error:", error);
        return;
      }

      if (!row) {
        db.run(
          "INSERT INTO users (username, password, role, bio, apiToken) VALUES ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin', '<b>administrator</b>', 'STATIC-ADMIN-TOKEN-123')"
        );
        db.run(
          "INSERT INTO users (username, password, role, bio, apiToken) VALUES ('demo', 'fe01ce2a7fbac8fafaed7c982a04e229', 'user', 'demo user', 'STATIC-DEMO-TOKEN-456')"
        );
      }
    });
  });
}

export function allQuery(sql: string): Promise<unknown[]> {
  return new Promise((resolve, reject) => {
    db.all(sql, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(rows);
    });
  });
}

export function getQuery(sql: string): Promise<any> {
  return new Promise((resolve, reject) => {
    db.get(sql, (error, row) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(row);
    });
  });
}

export function runQuery(sql: string): Promise<{ id?: number; changes?: number }> {
  return new Promise((resolve, reject) => {
    db.run(sql, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }

      resolve({
        id: this.lastID,
        changes: this.changes
      });
    });
  });
}