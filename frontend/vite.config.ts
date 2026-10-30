import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The backend runs on port 8000; the dev server forwards /api to it.
// ws: true lets Phase 2's live WebSocket go through the same proxy.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", ws: true },
    },
  },
});
