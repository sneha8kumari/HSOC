import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/incidents': 'http://localhost:8000',
      '/feedback': 'http://localhost:8000',
      '/knowledge': 'http://localhost:8000',
      '/models': 'http://localhost:8000',
      '/stream': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})
