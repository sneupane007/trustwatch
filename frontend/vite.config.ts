import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// The backend runs on port 8000; the dev server forwards /api to it.
// ws: true lets Phase 2's live WebSocket go through the same proxy.
// Backend on another machine, e.g. the victim VM: TRUSTWATCH_BACKEND=http://<vm-ip>:8000 npm run dev
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: loadEnv(mode, ".", "TRUSTWATCH_").TRUSTWATCH_BACKEND ?? "http://127.0.0.1:8000",
        ws: true,
      },
    },
  },
}));
