import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the API to a running ddosd (demo config listens on :8090).
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 1200 },
  server: { proxy: { "/api": process.env.DDOSD_API ?? "http://localhost:8090" } },
});
