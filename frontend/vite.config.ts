import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, Vite proxies API + WebSocket calls to the Python dashboard backend
// (default http://127.0.0.1:8080). Override with VITE_API_TARGET.
const target = process.env.VITE_API_TARGET || "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target, changeOrigin: true },
      "/ws": { target, ws: true, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
