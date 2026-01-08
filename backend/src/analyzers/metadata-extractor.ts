import crypto from 'crypto';
import type { FileMetadata } from '../types/index.js';

export async function extractMetadata(
  file: Express.Multer.File
): Promise<FileMetadata> {
  // Calculate SHA-256 hash
  const hash = crypto
    .createHash('sha256')
    .update(file.buffer)
    .digest('hex');

  return {
    filename: file.originalname,
    size: file.size,
    type: file.mimetype,
    lastModified: Date.now(),
    hash,
    created: new Date().toISOString(),
    modified: new Date().toISOString(),
    permissions: 'N/A (uploaded file)',
  };
}
