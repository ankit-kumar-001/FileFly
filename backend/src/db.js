import pkg from "pg";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, "..", ".env") });
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

export async function initDbSchema() {
  try {
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

      CREATE TABLE IF NOT EXISTS files (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        mime_type TEXT,
        size BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS transfers (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        file_id UUID REFERENCES files(id) ON DELETE CASCADE,
        transfer_code VARCHAR(6) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        downloads INT DEFAULT 0,
        max_downloads INT DEFAULT 100,
        is_active BOOLEAN DEFAULT true,
        file_count INT DEFAULT 1,
        files_metadata JSONB DEFAULT '[]'::jsonb,
        is_zipped BOOLEAN DEFAULT true
      );

      ALTER TABLE transfers ADD COLUMN IF NOT EXISTS file_count INT DEFAULT 1;
      ALTER TABLE transfers ADD COLUMN IF NOT EXISTS files_metadata JSONB DEFAULT '[]'::jsonb;
      ALTER TABLE transfers ADD COLUMN IF NOT EXISTS is_zipped BOOLEAN DEFAULT true;
    `);
    console.log("Database schema initialized and verified.");
  } catch (err) {
    console.warn("Database schema init notice:", err.message);
  }
}

export default pool;
