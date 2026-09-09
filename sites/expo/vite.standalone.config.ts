import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/postcss';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  root: fileURLToPath(new URL('./standalone', import.meta.url)),
  base: '/expo-assets/',
  plugins: [react()],
  css: { postcss: { plugins: [tailwindcss()] } },
  resolve: { alias: { '@': fileURLToPath(new URL('.', import.meta.url)) } },
  publicDir: fileURLToPath(new URL('./public', import.meta.url)),
  build: { outDir: '../dist-standalone', emptyOutDir: true },
});
