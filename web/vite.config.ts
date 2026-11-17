import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'sns-precompressed-wasm-dev',
      configureServer(server) {
        server.middlewares.use('/sns-zk.wasm', (req, res, next) => {
          const gzPath = path.resolve(__dirname, 'public', 'sns-zk.wasm.gz');
          if (!fs.existsSync(gzPath)) return next();
          res.setHeader('Content-Type', 'application/wasm');
          res.setHeader('Cache-Control', 'no-cache');
          const accept = String(req.headers['accept-encoding'] || '');
          const gzBytes = fs.readFileSync(gzPath);
          if (accept.includes('gzip')) {
            res.setHeader('Content-Encoding', 'gzip');
            res.end(gzBytes);
          } else {
            res.end(zlib.gunzipSync(gzBytes));
          }
        });
      },
    },
  ],
  worker: {
    format: 'es',
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom'],
          xterm: ['@xterm/xterm', '@xterm/addon-fit', '@xterm/addon-search', '@xterm/addon-web-links'],
          icons: ['lucide-react'],
        },
      },
    },
  },
});
