import multer from "multer";
import { nanoid } from "nanoid";
import pool from "../db.js";
import path from "path";
import crypto from "node:crypto";
import {
  multerFileFilter,
  sanitizeUploadedFile,
  safelyDeleteFile
} from "../middleware/fileSanitizer.js";

const MAX_ALLOWED_SIZE = 10 * 1024 * 1024 ; // 10MB 

const upload = multer({
  dest: "uploads/",
  limits: {
    fileSize: MAX_ALLOWED_SIZE
  },
  fileFilter: multerFileFilter
});

export const uploadFile = [
  (req, res, next) => {
    upload.single("file")(req, res, (err) => {
      if (err) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(413).json({ error: "File too large. Maximum size allowed is 10MB." });
        }
        return res.status(400).json({ error: err.message || "File upload failed." });
      }
      next();
    });
  },
  sanitizeUploadedFile,
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "Please select a file to upload." });
      }

      const code = crypto.randomInt(100000, 1000000).toString();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
      const maxDownloads = 100;

      const fileResult = await pool.query(
        `INSERT INTO files (original_name, stored_name, mime_type, size)
         VALUES ($1,$2,$3,$4) RETURNING id`,
        [
          req.file.originalname,
          req.file.filename,
          req.file.mimetype,
          req.file.size
        ]
      );

      await pool.query(
        `INSERT INTO transfers (file_id, transfer_code, expires_at, max_downloads)
         VALUES ($1,$2,$3,$4)`,
        [fileResult.rows[0].id, code, expiresAt, maxDownloads]
      );

      res.json({
        transferCode: code,
        expiresAt,
        maxDownloads
      });
    } catch (err) {
      if (req.file?.path) {
        await safelyDeleteFile(req.file.path);
      }
      res.status(500).json({ error: err.message });
    }
  }
];

export const downloadFile = async (req, res) => {
  try {
    const { code } = req.params;

    const result = await pool.query(
      `SELECT f.*, t.*
       FROM transfers t
       JOIN files f ON t.file_id = f.id
       WHERE t.transfer_code = $1 AND t.is_active = true`,
      [code]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ message: "Invalid or expired code" });
    
    const transfer = result.rows[0];

    if (new Date() > transfer.expires_at)
      return res.status(410).json({ message: "Link expired" });

    await pool.query(
      `UPDATE transfers
       SET downloads = downloads + 1,
           is_active = (downloads + 1 < max_downloads)
       WHERE id = $1`,
      [transfer.id]
    );

    const safeFilename = encodeURIComponent(transfer.original_name);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${transfer.original_name}"; filename*=UTF-8''${safeFilename}`
    );
    res.sendFile(path.resolve(`uploads/${transfer.stored_name}`));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};