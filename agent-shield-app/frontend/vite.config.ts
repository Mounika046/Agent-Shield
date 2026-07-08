import { fileURLToPath, URL } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: [
      {
        find: /^@\/(.*)$/,
        replacement: fileURLToPath(new URL('./src/$1', import.meta.url)),
      },
    ],
    dedupe: ['react', 'react-dom'],
  },
  server: {
    port: 5200,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8070',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
});
