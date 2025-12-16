import { registerAs } from '@nestjs/config';

export default registerAs('dental', () => ({
  // Upload & Storage Paths
  uploadDir: process.env.DENTAL_UPLOAD_DIR || 'uploads/dental/temp',
  outputDir: process.env.DENTAL_OUTPUT_DIR || 'uploads/dental/converted',

  // Encryption
  encryptionKey:
    process.env.DENTAL_ENCRYPTION_KEY || 'qW9xZ2tL8mP4rN6vB3jF5hY7cT2kD9wE', // 32 chars

  // Conversion Settings
  simplificationRatio: 0.3,
  errorThreshold: 0.0005,
  timeout: 300000, // 5 mins

  // Worker Pool
  minThreads: parseInt(process.env.PISCINA_MIN_THREADS || '0', 10),
  maxThreads: parseInt(process.env.PISCINA_MAX_THREADS || '0', 10),
}));
