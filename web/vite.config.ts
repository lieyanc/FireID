import fs from "node:fs"
import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig, type Plugin, type ProxyOptions } from "vite"

// Override with FIREID_BACKEND=http://host:port when the API listens elsewhere.
const backend = process.env.FIREID_BACKEND ?? "http://127.0.0.1:8099"

// The Go binary embeds web/dist with `//go:embed all:dist`, so the directory
// must never be empty. emptyOutDir wipes the committed .gitkeep on every build;
// write it back once the bundle is on disk.
function keepDistPlaceholder(): Plugin {
  let outDir = "dist"
  return {
    name: "fireid:keep-dist-placeholder",
    apply: "build",
    configResolved(config) {
      outDir = path.resolve(config.root, config.build.outDir)
    },
    closeBundle() {
      fs.mkdirSync(outDir, { recursive: true })
      fs.writeFileSync(path.join(outDir, ".gitkeep"), "")
    },
  }
}

// Paths the backend owns. Keys starting with "^" are regular expressions
// matched against the request URL; they are anchored on a path boundary so
// "/login" does not swallow UI routes that merely share the prefix.
const backendPaths = [
  "api",
  "health",
  "login",
  "oidc",
  "authorize",
  "oauth",
  "userinfo",
  "keys",
  "\\.well-known",
  "end_session",
  "revoke",
]
// The backend refuses state-changing requests whose Origin is not its public
// URL (403 cross_site). The dev server is another origin, so present the
// backend's own; run the backend with publicUrl at FIREID_BACKEND.
const backendOrigin = new URL(backend).origin
const proxy = Object.fromEntries(
  backendPaths.map((p) => [
    `^/${p}(?:[/?#]|$)`,
    {
      target: backend,
      configure: (server) => {
        server.on("proxyReq", (req) => {
          if (req.getHeader("origin")) req.setHeader("origin", backendOrigin)
        })
      },
    } satisfies ProxyOptions,
  ])
)

// https://vite.dev/config/
export default defineConfig({
  base: "/",
  plugins: [react(), tailwindcss(), keepDistPlaceholder()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // react-dom + react-router + react-query dominate the entry chunk.
    chunkSizeWarningLimit: 800,
  },
  server: { proxy },
})
