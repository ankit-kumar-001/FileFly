import express from "express";
import { uploadFile, downloadFile, getTransferInfo } from "../controllers/transfer.controller.js";
import { downloadRateLimiter } from "../middleware/rateLimiter.js";

const router = express.Router();

router.post("/upload", uploadFile);
router.get("/:code/info", getTransferInfo);
router.get("/:code", downloadRateLimiter, downloadFile);

export default router;
