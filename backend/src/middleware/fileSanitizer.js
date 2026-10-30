import fs from "fs";
import path from "path";

/**
 * List of known dangerous and executable extensions associated with malware,
 * scripts, and malicious binaries.
 */
export const DANGEROUS_EXTENSIONS = new Set([
  // Windows executables, binaries & libraries
  ".exe", ".dll", ".so", ".dylib", ".com", ".scr", ".pif", ".cpl", ".msi", ".msp", ".mst",
  ".sys", ".drv", ".ocx", ".gadget", ".hta", ".efi",

  // Scripts and batch files
  ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".wsh", ".ws", ".wsc",
  ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2", ".psm1", ".psd1",
  ".reg", ".inf", ".job",

  // Linux / Unix / macOS binaries and shell scripts
  ".sh", ".bash", ".zsh", ".csh", ".ksh", ".bin", ".run", ".out", ".elf",
  ".app", ".dmg", ".pkg", ".deb", ".rpm",

  // Web and server-side script files (potential web shells / RCE)
  ".php", ".php3", ".php4", ".php5", ".phtml", ".phar", ".pht", ".phps",
  ".jsp", ".jspx", ".jspa", ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx",
  ".cgi", ".pl", ".py", ".pyc", ".pyo", ".pyd", ".rb",

  // Java & Android executables / packages
  ".jar", ".class", ".apk", ".dex", ".xapk",

  // Browser extensions and disk images
  ".crx", ".xpi", ".iso", ".img", ".vhd", ".vhdx",

  // Macro-enabled Microsoft Office files
  ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm"
]);

/**
 * MIME types associated with executables, scripts, and malware payloads.
 */
export const DANGEROUS_MIME_TYPES = new Set([
  "application/x-msdownload",
  "application/x-msdos-program",
  "application/x-executable",
  "application/x-sharedlib",
  "application/x-pie-executable",
  "application/x-sh",
  "application/x-bash",
  "application/x-csh",
  "application/x-shar",
  "application/x-shellscript",
  "application/x-bat",
  "application/x-msdos-batch",
  "application/x-cmd",
  "application/x-msi",
  "application/x-apple-diskimage",
  "application/vnd.microsoft.portable-executable",
  "application/x-elf",
  "application/x-mach-binary",
  "application/x-dosexec",
  "application/x-php",
  "application/x-httpd-php",
  "text/x-shellscript",
  "text/x-php",
  "text/x-python",
  "text/x-perl",
  "text/x-ruby",
  "application/java-archive",
  "application/vnd.android.package-archive"
]);

/**
 * Sanitizes a filename:
 * - Strips directory traversal (path.basename)
 * - Removes null bytes and control characters
 * - Strips Unicode bidirectional overrides (RLO attack prevention)
 * - Replaces forbidden filesystem characters
 * - Enforces safe max length
 */
export function sanitizeFilename(filename) {
  if (!filename || typeof filename !== "string") {
    return "unnamed_file";
  }

  // 1. Strip any directory paths
  let cleanName = path.basename(filename);

  // 2. Remove null bytes and ASCII control characters (0x00 - 0x1F, 0x7F)
  cleanName = cleanName.replace(/[\x00-\x1f\x7f]/g, "");

  // 3. Remove Unicode bidirectional override characters (prevent RLO spoofing)
  cleanName = cleanName.replace(/[\u202A-\u202E\u2066-\u2069]/g, "");

  // 4. Replace forbidden filesystem characters with an underscore
  cleanName = cleanName.replace(/[/\\:*?"<>|]/g, "_");

  // 5. Trim leading/trailing dots and whitespace
  cleanName = cleanName.replace(/^[\s.]+|[\s.]+$/g, "");

  if (!cleanName) {
    cleanName = "unnamed_file";
  }

  // 6. Enforce safe length limit (255 chars)
  if (cleanName.length > 255) {
    const ext = path.extname(cleanName);
    const base = path.basename(cleanName, ext).slice(0, 255 - ext.length);
    cleanName = `${base}${ext}`;
  }

  return cleanName;
}

/**
 * Validates filename against malware extensions, double-extension cloaking,
 * and dangerous unicode spoofing.
 */
export function validateFilenameSecurity(filename) {
  if (!filename || typeof filename !== "string") {
    return {
      safe: false,
      reason: "Invalid or empty filename."
    };
  }

  // Detect Unicode bidirectional override characters (e.g. Right-to-Left Override spoofing)
  if (/[\u202A-\u202E\u2066-\u2069]/.test(filename)) {
    return {
      safe: false,
      reason: "Filename contains forbidden bidirectional override characters (potential spoofing attack)."
    };
  }

  const sanitized = sanitizeFilename(filename);

  // Inspect all extensions (split by '.') to prevent double-extension cloaking (e.g. file.exe.pdf or file.pdf.exe)
  const parts = sanitized.toLowerCase().split(".");
  if (parts.length > 1) {
    const finalExt = `.${parts[parts.length - 1]}`;
    if (DANGEROUS_EXTENSIONS.has(finalExt)) {
      return {
        safe: false,
        reason: `Malware or executable file extension '${finalExt}' is not permitted.`
      };
    }

    // Check intermediate extensions for cloaked executable payloads
    for (let i = 1; i < parts.length - 1; i++) {
      const middleExt = `.${parts[i]}`;
      if (DANGEROUS_EXTENSIONS.has(middleExt)) {
        return {
          safe: false,
          reason: `Disguised executable extension detected in filename ('${middleExt}').`
        };
      }
    }
  }

  return { safe: true, sanitizedName: sanitized };
}

/**
 * Deep inspection of the file content (magic numbers / signatures) on disk.
 * Catches executables and scripts even if disguised with innocent extensions.
 */
export async function detectMaliciousContent(filePath) {
  let fileHandle;
  try {
    fileHandle = await fs.promises.open(filePath, "r");
    const buffer = Buffer.alloc(512);
    const { bytesRead } = await fileHandle.read(buffer, 0, 512, 0);

    if (bytesRead < 2) {
      return { isMalicious: false };
    }

    // 1. Windows PE / DOS Executable: Starts with 'MZ' (0x4D, 0x5A)
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      return {
        isMalicious: true,
        reason: "Executable binary detected (Windows PE / DOS MZ signature)."
      };
    }

    // 2. Linux ELF Executable: Starts with 0x7F 'E' 'L' 'F' (0x7F, 0x45, 0x4C, 0x46)
    if (
      bytesRead >= 4 &&
      buffer[0] === 0x7f &&
      buffer[1] === 0x45 &&
      buffer[2] === 0x4c &&
      buffer[3] === 0x46
    ) {
      return {
        isMalicious: true,
        reason: "Executable binary detected (Linux ELF signature)."
      };
    }

    // 3. macOS Mach-O Executable / Java bytecode:
    if (bytesRead >= 4) {
      const magic32BE = buffer.readUInt32BE(0);
      const magic32LE = buffer.readUInt32LE(0);
      if (
        magic32BE === 0xfeedface ||
        magic32BE === 0xfeedfacf ||
        magic32LE === 0xfeedface ||
        magic32LE === 0xfeedfacf ||
        magic32BE === 0xcafebabe
      ) {
        return {
          isMalicious: true,
          reason: "Executable binary detected (Mach-O / Java bytecode signature)."
        };
      }
    }

    // 4. Unix Script Shebang: Starts with '#!' (0x23, 0x21)
    if (buffer[0] === 0x23 && buffer[1] === 0x21) {
      const headerStr = buffer.toString("utf8", 0, Math.min(bytesRead, 128)).toLowerCase();
      if (
        headerStr.includes("/sh") ||
        headerStr.includes("/bash") ||
        headerStr.includes("/zsh") ||
        headerStr.includes("/python") ||
        headerStr.includes("/perl") ||
        headerStr.includes("/ruby") ||
        headerStr.includes("/php") ||
        headerStr.includes("/node")
      ) {
        return {
          isMalicious: true,
          reason: "Executable script detected (Shebang signature)."
        };
      }
    }

    // 5. Embedded PHP Script: Starts with or contains '<?php' or '<?='
    const contentSample = buffer.toString("utf8", 0, Math.min(bytesRead, 512)).toLowerCase();
    if (contentSample.includes("<?php") || contentSample.includes("<?=")) {
      return {
        isMalicious: true,
        reason: "Server-side executable script detected (PHP tags)."
      };
    }

    return { isMalicious: false };
  } catch (err) {
    console.error("Error inspecting file content:", err);
    return { isMalicious: false };
  } finally {
    if (fileHandle) {
      try {
        await fileHandle.close();
      } catch (_) {}
    }
  }
}

/**
 * Safely unlinks a file from disk if it exists.
 */
export async function safelyDeleteFile(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) {
      await fs.promises.unlink(filePath);
    }
  } catch (err) {
    console.error(`Failed to delete suspicious file ${filePath}:`, err);
  }
}

export async function safelyDeleteAllFiles(files) {
  if (!files || !Array.isArray(files)) return;
  for (const file of files) {
    if (file?.path) {
      await safelyDeleteFile(file.path);
    }
  }
}

/**
 * Multer file filter to reject obviously dangerous files before writing to disk.
 */
export const multerFileFilter = (req, file, cb) => {
  // 1. Check filename
  const filenameCheck = validateFilenameSecurity(file.originalname);
  if (!filenameCheck.safe) {
    const err = new Error(`File '${file.originalname}' rejected: ${filenameCheck.reason}`);
    err.code = "MALWARE_DETECTED";
    err.statusCode = 400;
    return cb(err, false);
  }

  // 2. Check reported MIME type
  const mimeType = (file.mimetype || "").toLowerCase().trim();
  if (DANGEROUS_MIME_TYPES.has(mimeType)) {
    const err = new Error(`File '${file.originalname}' rejected: File type '${mimeType}' is blocked for security reasons.`);
    err.code = "MALWARE_DETECTED";
    err.statusCode = 400;
    return cb(err, false);
  }

  cb(null, true);
};

/**
 * Middleware executed after multer has stored the file(s).
 * Performs deep file content inspection and filename sanitization on all uploaded files.
 */
export const sanitizeUploadedFile = async (req, res, next) => {
  let files = req.normalizedFiles;
  if (!files) {
    if (req.files) {
      files = Array.isArray(req.files) ? req.files : Object.values(req.files).flat();
    } else if (req.file) {
      files = [req.file];
    } else {
      files = [];
    }
  }

  try {
    if (!files || files.length === 0) {
      return res.status(400).json({ error: "Please select at least one file to upload." });
    }

    for (const file of files) {
      const filePath = file.path;

      // 1. Validate and sanitize original filename
      const nameCheck = validateFilenameSecurity(file.originalname);
      if (!nameCheck.safe) {
        await safelyDeleteAllFiles(files);
        return res.status(400).json({ error: `File '${file.originalname}' rejected: ${nameCheck.reason}` });
      }

      // Set sanitized filename for storage/database
      file.originalname = nameCheck.sanitizedName;

      // 2. Check reported MIME type
      const mimeType = (file.mimetype || "").toLowerCase().trim();
      if (DANGEROUS_MIME_TYPES.has(mimeType)) {
        await safelyDeleteAllFiles(files);
        return res.status(400).json({
          error: `File '${file.originalname}' rejected: File type '${mimeType}' is blocked for security reasons.`
        });
      }

      // 3. Deep inspection of magic bytes
      const contentCheck = await detectMaliciousContent(filePath);
      if (contentCheck.isMalicious) {
        await safelyDeleteAllFiles(files);
        return res.status(400).json({
          error: `File '${file.originalname}' rejected: ${contentCheck.reason}`
        });
      }
    }

    req.validatedFiles = files;
    if (files.length === 1) {
      req.file = files[0];
    }
    next();
  } catch (error) {
    if (files && files.length > 0) {
      await safelyDeleteAllFiles(files);
    }
    console.error("Sanitization middleware error:", error);
    return res.status(500).json({ error: "File sanitization failed." });
  }
};

