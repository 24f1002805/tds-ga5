import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

let db;

export async function initDb() {
  db = await open({
    filename: process.env.DATABASE_PATH || './agent_state.db',
    driver: sqlite3.Database
  });

  await db.exec(`
    PRAGMA journal_mode = WAL;

    -- Q5 State Storage
    CREATE TABLE IF NOT EXISTS q5_executions (
      runId TEXT PRIMARY KEY,
      stepCount INTEGER DEFAULT 0,
      spentBudget REAL DEFAULT 0.0,
      historyJson TEXT NOT NULL
    );

    -- Q9 State Storage
    CREATE TABLE IF NOT EXISTS q9_evaluations (
      evaluationId TEXT PRIMARY KEY,
      inputDigest TEXT NOT NULL,
      receiptVerifier TEXT NOT NULL,
      proposalsJson TEXT NOT NULL
    );

    -- Q10 State Storage
    CREATE TABLE IF NOT EXISTS q10_tasks (
      taskId TEXT PRIMARY KEY,
      principal TEXT NOT NULL,
      contextId TEXT NOT NULL,
      batchId TEXT NOT NULL,
      state TEXT NOT NULL,
      taskJson TEXT NOT NULL,
      msgHash TEXT NOT NULL
    );

    -- Q11 State Storage
    CREATE TABLE IF NOT EXISTS q11_runs (
      runId TEXT PRIMARY KEY,
      inputHash TEXT NOT NULL,
      status TEXT NOT NULL,
      runDataJson TEXT NOT NULL,
      otlpJson TEXT NOT NULL
    );
  `);

  return db;
}

export function getDb() {
  if (!db) throw new Error("Database not initialized");
  return db;
}
