import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Output goes into the Go package that embeds it (internal/dashboard).
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../internal/dashboard/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1200,
  },
  server: {
    // `bun run dev` proxies API calls to a hub admin port reached through an SSH tunnel.
    proxy: { '/admin': 'http://127.0.0.1:9090' },
  },
})
