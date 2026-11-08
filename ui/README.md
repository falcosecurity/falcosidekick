# falcosidekick UI

React 19 + TypeScript + Tailwind CSS 4, built with Bun. Scaffold-aligned to `bun init --react=shadcn`.

## Prerequisites

- [Bun](https://bun.com) >= 1.3.0. Install via `curl -fsSL https://bun.com/install | bash` or `brew install oven-sh/bun/bun`.

No Node.js or npm is required.

## Scripts

```sh
bun install --frozen-lockfile   # install dependencies
bun run dev                     # Bun.serve dev server (:5173) with HMR and API proxy
bun run build                   # production build -> ./dist
bun run lint                    # eslint
bun run typecheck               # tsc --noEmit
bun test                        # unit and component tests via Bun test + happy-dom
```

## Dev server

`bun run dev` starts [`src/index.ts`](src/index.ts), which:
- serves `src/index.html` at `/*` with HMR and React Fast Refresh,
- proxies `/api/**`, `/healthz`, `/version`, `/metrics` to `http://localhost:2801` (falcosidekick backend).

Override backend URL: `FALCOSIDEKICK_BACKEND=...`. Override dev port: `UI_DEV_PORT=...`.

## Production build

`bun run build` runs [`build.ts`](build.ts), which:
1. Cleans `dist/`.
2. Calls `Bun.build` with [`bun-plugin-tailwind`](https://www.npmjs.com/package/bun-plugin-tailwind) registered, targeting every `src/**/*.html` entrypoint.
3. Emits minified JS + CSS + source maps + content-hashed assets.

The resulting `dist/` tree is consumed by the Go `go:embed` in [`embed.go`](embed.go) when the binary is built with `-tags=builtinui`.

## shadcn components

```sh
bunx shadcn@latest add <component>
```

Components land in `src/components/ui/`. The shadcn config is in [`components.json`](components.json); the Tailwind source is [`styles/globals.css`](styles/globals.css).

## Adding new dependencies

```sh
bun add <pkg>        # runtime
bun add -d <pkg>     # dev
```

Remember to commit `bun.lock`.

## Layout

```
bunfig.toml     # Bun config + tailwind plugin registration
build.ts        # production build script (used by `bun run build`)
bun-env.d.ts    # ambient module declarations for *.css, *.svg
tsconfig.json   # single scaffold-shape tsconfig
package.json
bun.lock        # committed text lockfile
components.json # shadcn config
eslint.config.js
styles/
  globals.css   # Tailwind entrypoint + theme variables
src/
  index.html    # bundler entrypoint
  index.ts      # Bun.serve dev server
  frontend.tsx  # React bootstrap
  App.tsx
  index.css     # imports ../styles/globals.css
  favicon.svg
  components/ui/
  lib/
```

The repo-root files `doc.go`, `embed.go`, `embed_stub.go`, and the embed tests form the Go `ui` package that wires `dist/*` into the falcosidekick binary. They are intentionally in the same directory as the UI source because `go:embed` cannot traverse parent directories.

## Page tree (post-Commit 10)

| Route | Page | Notes |
|-------|------|-------|
| `/` | Dashboard | Counter cards, top rules, top sources, output status grid. |
| `/events` | Events | Filtered table with side-drawer detail. |
| `/pipeline` | Pipeline | Read-only React Flow graph with output status badges. |
| `/settings` | Settings | Version info and UI preferences. |
| `/login` | Sign in | Scaffold until 9d (auth + JWT) lands. |
| `*` | 404 | Not found. |

All authenticated routes are wrapped in `<AuthGuard>` ([`src/components/auth/auth-guard.tsx`](src/components/auth/auth-guard.tsx)) which is a pass-through while `auth.enabled=false` in the backend config.

## State and data fetching

- HTTP boundary: [`src/lib/api-client.ts`](src/lib/api-client.ts). ESLint forbids raw `fetch` / `axios` outside this file.
- Query cache: [TanStack Query](https://tanstack.com/query) via [`src/lib/query-client.ts`](src/lib/query-client.ts).
- Stores (Zustand): [`src/stores/auth-store.ts`](src/stores/auth-store.ts), [`src/stores/ui-store.ts`](src/stores/ui-store.ts), [`src/stores/pipeline-store.ts`](src/stores/pipeline-store.ts).

## Live event feed

`/events` polls `GET /api/v1/events/search` via [`src/hooks/use-events.ts`](src/hooks/use-events.ts). The shared refresh control defaults to 15 seconds and can disable automatic polling. WebSocket streaming is not implemented.

## Testing

```sh
bun test                         # runs all *.test.ts / *.test.tsx files
bun test path/to/file.test.tsx   # single file
```

Harness: `@testing-library/react` over `happy-dom`, wired through `bunfig.toml`'s `[test] preload`. Testing matchers are augmented via [`src/test/jest-dom.d.ts`](src/test/jest-dom.d.ts).

## Theme

Colors live as CSS custom properties in [`styles/globals.css`](styles/globals.css). The primary accent is Falco's official teal `#00AEC7` (see `--brand` and `--ring`). shadcn "new-york" neutral is the base.
