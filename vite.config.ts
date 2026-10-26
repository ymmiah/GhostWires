import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// NOTE (Mk.IV): API keys are NEVER injected into the client bundle.
// All AI calls go through the Express server (/api/ai/*), which reads keys from env.
export default defineConfig({
    plugins: [react()],
    resolve: { alias: { '@': path.resolve(__dirname, '.') } },
    build: { outDir: 'dist', emptyOutDir: true },
});
