import express from "express";
import cors from "cors";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from "url";
import transferRoutes from "./routes/transfer.routes.js";
import fs from "fs";
import { initDbSchema } from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, "..", ".env") });

initDbSchema();

const app = express();

app.use(cors({
  origin: process.env.FRONTEND_URL ,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

const uploadsPath = path.join(__dirname, "..", "uploads");
fs.mkdirSync(uploadsPath, { recursive: true });

app.use("/api/transfers", transferRoutes);

// this are the files which can be accessed by the browser
app.use("/uploads", express.static(uploadsPath));

const frontendPath = path.resolve(__dirname, "..", "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

const port = process.env.PORT || 3001;
const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

process.on('SIGINT', () => {
  console.log('Shutting down server...');
  server.close(() => {
    console.log('Server closed. Port 3001 released.');
    process.exit(0);
  });
});


app.use((err, req, res, next) => {
  if (err.name === "MulterError") {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ error: "File too large. Maximum size allowed is 10MB." });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err.statusCode || err.status) {
    return res.status(err.statusCode || err.status).json({ error: err.message });
  }
  console.error("Internal Server Error:", err);
  res.status(500).json({ error: "Something went wrong! details: " + err.message });
});

