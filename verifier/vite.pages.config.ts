import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const githubPages = process.env.GITHUB_ACTIONS === 'true';

export default defineConfig({
  root: 'pages-src',
  base: githubPages ? '/technocore-room-slot-watcher/' : '/',
  plugins: [react()],
  build: {
    outDir: '../dist-pages',
    emptyOutDir: true,
  },
});
