const fs = require("fs");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const crypto = require("crypto");
const pool = require("../config/database");
const logger = require("../utils/logger");
const { create } = require("domain");

function generateRandomString(length = 25) {
  return crypto
    .randomBytes(length)
    .toString("base64")
    .replace(/\W/g, "")
    .substring(0, length);
}

function formatFileSize(bytes) {
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  if (bytes === 0) return "0 B";
  const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

async function uploadDocuments(files, uploadedBy, verifiedBy = 1) {
  const uploadedResults = [];

  // Buat direktori target sekali di awal
  const destinationDir = path.join(
    __dirname,
    "..",
    "public",
    "storage",
    "documents"
  );

  try {
    if (!fs.existsSync(destinationDir)) {
      fs.mkdirSync(destinationDir, { recursive: true });
      logger.info(`| uploadDocuments | - Folder dibuat: ${destinationDir}`);
    }
  } catch (err) {
    logger.error(`| uploadDocuments | - Gagal membuat folder: ${err.message}`);
    throw new Error("Gagal menyiapkan direktori penyimpanan dokumen.");
  }

  // Proses masing-masing file
  for (const file of files) {
    try {
      const extension = path.extname(file.originalname);
      const randomName = generateRandomString() + extension;
      const destinationPath = path.join(destinationDir, randomName);

      fs.renameSync(file.path, destinationPath); // move file

      const relativePath = `storage/documents/${randomName}`;
      const fileUrl = `${process.env.APP_URL}/${relativePath}`;
      const mimeType = file.mimetype;
      const fileSize = formatFileSize(file.size);
      const fileId = uuidv4();

      const result = await pool.query(
        `INSERT INTO documents (
          id, uploaded_by, verified_by,
          file_id, file_name, file_path,
          file_url, file_mime_type, file_size
        ) VALUES (
          DEFAULT, $1, $2,
          $3, $4, $5,
          $6, $7, $8
        ) RETURNING id, created_at, updated_at, deleted_at`,
        [
          uploadedBy,
          verifiedBy,
          fileId,
          randomName,
          relativePath,
          fileUrl,
          mimeType,
          fileSize,
        ]
      );

      uploadedResults.push({
        id: result.rows[0].id,
        file_id: fileId,
        filename: randomName,
        file_path: relativePath,
        file_url: fileUrl,
        file_mime_type: mimeType,
        file_size: fileSize,
        created_at: result.rows[0].created_at,
        updated_at: result.rows[0].updated_at,
        deleted_at: result.rows[0].deleted_at,
      });

      logger.info(`| uploadDocuments | - Success: ${randomName}`);
    } catch (err) {
      logger.error(
        `| uploadDocuments | - Failed on file ${file.originalname}: ${err.message}`
      );
    }
  }

  return uploadedResults;
}

async function deleteDocuments(documentIds = []) {
  const deleted = [];

  for (const id of documentIds) {
    try {
      const { rows } = await pool.query(
        `SELECT file_path FROM documents WHERE id = $1 AND deleted_at IS NULL`,
        [id]
      );

      if (rows.length === 0) {
        logger.warn(`| deleteDocuments | - Dokumen ID ${id} tidak ditemukan.`);
        continue;
      }

      const filePath = path.join(__dirname, "..", "public", rows[0].file_path);

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      } else {
        logger.warn(
          `| deleteDocuments | - File tidak ditemukan di path: ${filePath}`
        );
      }

      await pool.query(
        `UPDATE documents SET deleted_at = NOW() WHERE id = $1`,
        [id]
      );

      deleted.push(id);
      logger.info(`| deleteDocuments | - Dokumen ${id} berhasil dihapus.`);
    } catch (error) {
      logger.error(
        `| deleteDocuments | - Gagal menghapus dokumen ${id}: ${error.message}`
      );
    }
  }

  return deleted;
}

module.exports = { uploadDocuments, deleteDocuments };
