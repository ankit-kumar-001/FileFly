import multer from "multer";
import pool from "../db.js";
import path from "path";
import crypto from "node:crypto";
import fs from "fs";
import os from "os";
import { Zip, extract } from "zip-lib";
import {
  multerFileFilter,
  sanitizeUploadedFile,
  safelyDeleteFile,
  safelyDeleteAllFiles
} from "../middleware/fileSanitizer.js";

const uploadsPath = path.resolve("uploads");
const uploadTempDir = path.resolve("uploads/temp");

fs.mkdirSync(uploadTempDir, { recursive: true });

const upload = multer({
  dest: uploadTempDir,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB per file
  },
  fileFilter: multerFileFilter
});

const uploadMiddleware = upload.fields([
  { name: "files", maxCount: 20 },
  { name: "file", maxCount: 20 }
]);

export const uploadFile = [
  (req, res, next) => {
    uploadMiddleware(req, res, (err) => {
      if (err) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(413).json({ error: "File too large. Maximum size allowed is 10MB per file." });
        }
        if (err.code === "LIMIT_UNEXPECTED_FILE") {
          return res.status(400).json({ error: "Too many files uploaded (maximum 20 files allowed)." });
        }
        return res.status(400).json({ error: err.message || "File upload failed." });
      }

      // Normalize files array from either 'files' or 'file' fields
      const allFiles = [
        ...(req.files?.files || []),
        ...(req.files?.file || [])
      ];
      
      req.normalizedFiles = allFiles;
      next();
    });
  },
  sanitizeUploadedFile,
  async (req, res) => {
    const files = req.validatedFiles || [];
    if (!files.length) {
      return res.status(400).json({ error: "Please select at least one file to upload." });
    }

    let storedZipPath = null;
    try {
      await fs.promises.mkdir(uploadsPath, { recursive: true });

      // 1. Always zip files using zip-lib (even a single file for maximum storage efficiency)
      const zip = new Zip();
      const usedNames = new Set();

      for (const file of files) {
        let entryName = file.originalname;
        if (usedNames.has(entryName)) {
          const ext = path.extname(entryName);
          const base = path.basename(entryName, ext);
          let counter = 1;
          while (usedNames.has(`${base}_${counter}${ext}`)) {
            counter++;
          }
          entryName = `${base}_${counter}${ext}`;
          file.originalname = entryName;
        }
        usedNames.add(entryName);
        zip.addFile(file.path, entryName);
      }

      const storedZipName = `${crypto.randomUUID()}.zip`;
      storedZipPath = path.join(uploadsPath, storedZipName);
      await zip.archive(storedZipPath);

      // Clean up uncompressed temporary upload files
      await safelyDeleteAllFiles(files);

      const zipStats = await fs.promises.stat(storedZipPath);
      const zipSize = zipStats.size;

      // 2. Prepare database records
      const code = crypto.randomInt(100000, 1000000).toString();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
      const maxDownloads = 100;

      const displayName = files.length === 1
        ? files[0].originalname
        : `${files[0].originalname} (+${files.length - 1} more)`;

      const primaryMimeType = files.length === 1
        ? files[0].mimetype || "application/octet-stream"
        : "application/zip";

      const filesMetadata = files.map(f => ({
        original_name: f.originalname,
        mime_type: f.mimetype || "application/octet-stream",
        size: f.size
      }));

      const fileResult = await pool.query(
        `INSERT INTO files (original_name, stored_name, mime_type, size)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [
          displayName,
          storedZipName,
          primaryMimeType,
          zipSize
        ]
      );

      // Update transfer table with file_count, files_metadata, and is_zipped
      await pool.query(
        `INSERT INTO transfers (file_id, transfer_code, expires_at, max_downloads, file_count, files_metadata, is_zipped)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          fileResult.rows[0].id,
          code,
          expiresAt,
          maxDownloads,
          files.length,
          JSON.stringify(filesMetadata),
          true
        ]
      );

      res.json({
        transferCode: code,
        fileCount: files.length,
        files: filesMetadata,
        expiresAt,
        maxDownloads
      });
    } catch (err) {
      if (storedZipPath) {
        await safelyDeleteFile(storedZipPath);
      }
      await safelyDeleteAllFiles(files);
      console.error("Upload controller error:", err);
      res.status(500).json({ error: err.message });
    }
  }
];

export const getTransferInfo = async (req, res) => {
  try {
    const { code } = req.params;

    const result = await pool.query(
      `SELECT f.original_name as file_original_name, f.size as file_size, f.mime_type as file_mime_type,
              t.id, t.transfer_code, t.expires_at, t.downloads, t.max_downloads, t.is_active,
              t.file_count, t.files_metadata, t.is_zipped
       FROM transfers t
       JOIN files f ON t.file_id = f.id
       WHERE t.transfer_code = $1 AND t.is_active = true`,
      [code]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Invalid or expired code" });
    }

    const transfer = result.rows[0];

    if (new Date() > transfer.expires_at) {
      return res.status(410).json({ message: "Link expired" });
    } 

    let files = [];
    if (transfer.files_metadata && Array.isArray(transfer.files_metadata) && transfer.files_metadata.length > 0) {
      files = transfer.files_metadata;
    } else {
      files = [{
        original_name: transfer.file_original_name,
        size: transfer.file_size,
        mime_type: transfer.file_mime_type
      }];
    }

    res.json({
      transferCode: transfer.transfer_code,
      fileCount: transfer.file_count || files.length,
      files,
      expiresAt: transfer.expires_at,
      maxDownloads: transfer.max_downloads,
      downloads: transfer.downloads
    });
  } catch (err) {
    console.error("Transfer info error:", err);
    res.status(500).json({ error: err.message });
  }
};

export const downloadFile = async (req, res) => {
  let tempExtractDir = null;
  try {
    const { code } = req.params;

    const result = await pool.query(
      `SELECT f.original_name as file_original_name, f.stored_name, f.mime_type as file_mime_type, f.size as file_size,
              t.*
       FROM transfers t
       JOIN files f ON t.file_id = f.id
       WHERE t.transfer_code = $1 AND t.is_active = true`,
      [code]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Invalid or expired code" });
    }

    const transfer = result.rows[0];

    if (new Date() > transfer.expires_at) {
      return res.status(410).json({ message: "Link expired" });
    }

    const storedFilePath = path.resolve(`uploads/${transfer.stored_name}`);
    if (!fs.existsSync(storedFilePath)) {
      return res.status(404).json({ message: "File not found on server" });
    }

    const isZipped = transfer.is_zipped !== false && transfer.stored_name.endsWith(".zip");

    if (!isZipped) {
      // Legacy unzipped file handling
      await pool.query(
        `UPDATE transfers
         SET downloads = downloads + 1,
             is_active = (downloads + 1 < max_downloads)
         WHERE id = $1`,
        [transfer.id]
      );

      const safeFilename = encodeURIComponent(transfer.file_original_name);
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${transfer.file_original_name}"; filename*=UTF-8''${safeFilename}`
      );
      return res.sendFile(storedFilePath);
    }

    //  Unzip using zip-lib before download 
    const tempDirRaw = await fs.promises.mkdtemp(path.join(os.tmpdir(), "filefly-dl-"));
    tempExtractDir = await fs.promises.realpath(tempDirRaw);

    await extract(storedFilePath, tempExtractDir);

    const extractedFiles = await fs.promises.readdir(tempExtractDir);
    if (!extractedFiles.length) {
      await fs.promises.rm(tempExtractDir, { recursive: true, force: true }).catch(() => {});
      return res.status(500).json({ message: "Archive was empty" });
    }

    let targetFileName = null;
    let targetMimeType = "application/octet-stream";

    // If specific file requested via query parameter
    if (req.query.file) {
      const requested = decodeURIComponent(req.query.file);
      if (extractedFiles.includes(requested)) {
        targetFileName = requested;
      }
    }

    // Default to the single file or first file
    if (!targetFileName) {
      targetFileName = extractedFiles[0];
    }

    // Match original MIME type from transfer metadata
    let filesMeta = [];
    try {
      filesMeta = Array.isArray(transfer.files_metadata)
        ? transfer.files_metadata
        : JSON.parse(transfer.files_metadata || "[]");
    } catch (_) {}

    const meta = filesMeta.find(m => m.original_name === targetFileName);
    if (meta && meta.mime_type) {
      targetMimeType = meta.mime_type;
    } else if (transfer.file_count === 1 && transfer.file_mime_type) {
      targetMimeType = transfer.file_mime_type;
    }

    const filePathToServe = path.join(tempExtractDir, targetFileName);

    // Update download count
    await pool.query(
      `UPDATE transfers
       SET downloads = downloads + 1,
           is_active = (downloads + 1 < max_downloads)
       WHERE id = $1`,
      [transfer.id]
    );

    const safeFilename = encodeURIComponent(targetFileName);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${targetFileName}"; filename*=UTF-8''${safeFilename}`
    );
    res.setHeader("Content-Type", targetMimeType);

    res.sendFile(filePathToServe, async (sendErr) => {
      // Clean up extracted temporary folder after download
      if (tempExtractDir) {
        await fs.promises.rm(tempExtractDir, { recursive: true, force: true }).catch(() => {});
      }
      if (sendErr && !res.headersSent) {
        console.error("Error sending unzipped file:", sendErr);
        res.status(500).json({ error: "Failed to download file" });
      }
    });
  } catch (err) {
    if (tempExtractDir) {
      await fs.promises.rm(tempExtractDir, { recursive: true, force: true }).catch(() => {});
    }
    console.error("Download error:", err);
    res.status(500).json({ error: err.message });
  }
};