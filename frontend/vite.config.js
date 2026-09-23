import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Local dev: proxy API calls to the FastAPI backend, so the app works without CORS.
export default defineConfig({
  // Override with VITE_BASE (e.g. /network-mapper/) when deploying to a
  // subpath such as GitHub Pages. Defaults to / for nginx/root deployments.
  base: process.env.VITE_BASE || '/',
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_PROXY_TARGET || 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})