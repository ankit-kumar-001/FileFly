# FileFly ✈️

> A fast, minimal, passcode-based file sharing web application.

FileFly lets you transfer files quickly without creating accounts, generating complex download links, or navigating bloated interfaces. Simply upload a file, receive a **6-digit PIN**, and share the code with the recipient.

---

## 📸 How It Works

```
 📤 Sender                         ⚙️ FileFly Backend                        📥 Receiver
┌─────────┐   1. Upload File     ┌─────────────────────┐   3. Input Code   ┌──────────┐
│ User A  │ ───────────────────► │ Express / Multer    │ ◄──────────────── │  User B  │
└─────────┘                      └──────────┬──────────┘                   └──────────┘
                                            │
                                 2. Save File & DB Record
                                 Generate 6-digit PIN (10m TTL)
```

1. **Upload**: Select any file (up to 10MB). FileFly stores the payload and generates a unique **6-digit passcode**.
2. **Share**: Send the 6-digit code to your recipient.
3. **Receive**: The receiver inputs the code on the web interface to instantly download the file.
4. **Auto-Expire**: Transfer links automatically expire after **10 minutes** or upon hitting download limits.

---

## ⚡ Key Features

- **Multi-File Uploads**: Upload multiple files simultaneously with individual and bulk downloading.
- **Efficient Zipped Storage (`zip-lib`)**: Every upload (whether 1 file or multiple) is compressed using `zip-lib` and stored as a `.zip` archive on the server to maximize storage efficiency. Files are automatically unzipped on-the-fly before download so recipients receive clean, uncompressed files.
- **Passcode Sharing**: Clean 6-digit numeric codes instead of long, ugly URLs.
- **Auto-Expiring Files**: Enforces a strict 10-minute expiration window for privacy and storage hygiene.
- **Malware & File Sanitization**: Multi-layer security layer against dangerous uploads — client-side checks, extension and MIME blocklisting, double-extension cloaking protection, Unicode RLO/path traversal neutralization, and deep magic-byte inspection (PE, ELF, Mach-O, scripts) with automatic server disk purging.
- **IP Rate Limiting**: Built-in Redis sliding window rate limiter (**30 downloads/hr per IP**) to safeguard against abuse and automated scraping.
- **Relational Metadata**: PostgreSQL tracks file metadata, MIME types, transfer states, download counts, and expiration timestamps.

---

## 🛠 Tech Stack

| Layer | Technology | Description |
| :--- | :--- | :--- |
| **Backend API** | Node.js, Express | RESTful routes, file streaming, and static asset serving |
| **Database** | PostgreSQL | Persistent relational store for file and transfer metadata |
| **Cache & Rate Limiting** | Redis (`ioredis`) | In-memory store handling IP download rate limits |
| **Compression & Storage** | `zip-lib` | Compresses all stored files for maximum storage efficiency; on-the-fly unzipping on download |
| **Security & Sanitization** | Custom Middleware | File extension/MIME validation, magic-byte inspection & filename cleansing |
| **File Handling** | Multer | Multipart/form-data middleware for handling disk uploads |
| **Frontend** | HTML5, CSS3, JavaScript | Lightweight zero-dependency client UI |

---

## 📁 Project Structure

```text
FileFly/
├── backend/
│   ├── src/
│   │   ├── controllers/    # Upload and download request logic
│   │   ├── middleware/     # Redis rate limiter & file sanitization middleware
│   │   ├── routes/         # API endpoint definitions
│   │   ├── db.js           # PostgreSQL connection pool
│   │   ├── redis.js        # Redis connection instance
│   │   └── server.js       # App entry point & static file server
│   ├── schema.sql          # PostgreSQL table definitions
│   └── .env.example        # Environment variable template
├── frontend/
│   ├── index.html          # Clean client interface
│   ├── script.js           # UI interaction and API fetch calls
│   └── style.css           # UI layout and styling
└── README.md
```

---

## 🔌 API Reference

### Upload File
```http
POST /api/transfers/upload
```
- **Content-Type**: `multipart/form-data`
- **Body**: `file` (Max 10MB)

**Response `200 OK`**:
```json
{
  "transferCode": "482910",
  "expiresAt": "2026-10-08T19:00:00.000Z",
  "maxDownloads": 100
}
```

---

### Download File
```http
GET /api/transfers/:code
```
- **Params**: `code` (6-digit numeric passkey)

**Response**:
- `200 OK`: File binary stream with `Content-Disposition: attachment` header
- `404 Not Found`: Invalid or expired transfer code
- `410 Gone`: Expiration timestamp passed
- `429 Too Many Requests`: Rate limit reached (30 downloads/hr per IP)

---

## 🚀 Getting Started

### Local Setup

#### Prerequisites
- **Node.js** (v18+)
- **PostgreSQL**
- **Redis**

#### 1. Configuration
Navigate to the backend directory and set up environment variables:

```bash
cd backend
cp .env.example .env
```

Example `.env`:
```env
PORT=3001
DATABASE_URL=postgresql://user:password@localhost:5432/filefly
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
FRONTEND_URL=*
```

#### 2. Database Initialization
Run the database schema script:

```bash
psql -d filefly -f schema.sql
```

#### 3. Run the App
Start Redis (`redis-server`), then launch the Node server:

```bash
npm install
npm start
```

Open `http://localhost:3001` in your browser.

---

## 📊 Database Schema

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  mime_type TEXT,
  size BIGINT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE transfers (
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
```

---

## 📄 License

[ISC](LICENSE)
