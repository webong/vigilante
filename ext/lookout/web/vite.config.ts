import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import { tanstackRouter } from "@tanstack/router-plugin/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// ext/lookout embeds dist/app and serves it under /lookout/. In dev, API
// calls go to a local vigilante with the lookout plugin enabled.
export default defineConfig({
  base: "/lookout/",
  plugins: [tanstackRouter({ target: "react", autoCodeSplitting: true }), react(), tailwindcss()],
  build: { outDir: "dist/app", emptyOutDir: true },
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "./src"),
    },
  },
  server: {
    proxy: {
      "/lookout/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
        // The server rejects cross-origin writes. In dev the page is on :5180,
        // so make the proxied request look like it came from the server itself.
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq) => {
            proxyReq.setHeader("origin", "http://127.0.0.1:8080")
          })
        },
      },
    },
  },
})
