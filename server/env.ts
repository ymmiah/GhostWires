// Load .env before any other module reads process.env (Node ≥ 20.12 built-in; no dotenv dependency).
// Variables already present in the real environment always win.
import fs from 'node:fs';
if (fs.existsSync('.env') && typeof (process as any).loadEnvFile === 'function') (process as any).loadEnvFile('.env');
