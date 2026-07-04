import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { writeFileSync } from "fs";

const buildStamp = new Date().toISOString();

export default defineConfig({
  plugins: [
    react(),
    {
      name: "build-info",
      config() {
        return {
          define: {
            __BUILD_STAMP__: JSON.stringify(buildStamp),
          },
        };
      },
      closeBundle() {
        const payload = JSON.stringify({ builtAt: buildStamp }, null, 2);
        writeFileSync(path.resolve(__dirname, "dist/build-info.json"), payload);
      },
    },
  ],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
