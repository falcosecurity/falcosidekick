import { serve } from "bun"
import index from "./index.html"

const BACKEND = Bun.env.FALCOSIDEKICK_BACKEND ?? "http://localhost:2801"
const PORT = Number(Bun.env.UI_DEV_PORT ?? 5173)

async function proxy(req: Request): Promise<Response> {
  const url = new URL(req.url)
  const target = new URL(url.pathname + url.search, BACKEND)
  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: req.headers,
      body: req.body,
    })
    const headers = new Headers(upstream.headers)
    headers.delete("content-encoding")
    headers.delete("content-length")
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    })
  } catch (err) {
    return Response.json(
      { error: "backend unreachable", backend: BACKEND, detail: String(err) },
      { status: 502 },
    )
  }
}

const server = serve({
  port: PORT,
  routes: {
    "/api/*": proxy,
    "/healthz": proxy,
    "/version": proxy,
    "/metrics": proxy,
    "/*": index,
  },
  development: Bun.env.NODE_ENV !== "production" && {
    hmr: true,
    console: true,
  },
})

console.log(`🐇 falcosidekick UI dev server: ${server.url} -> backend ${BACKEND}`)
