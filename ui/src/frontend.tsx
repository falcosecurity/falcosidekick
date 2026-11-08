import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import App from "./App"
import "./index.css"

const elem = document.getElementById("root")!
const app = (
  <StrictMode>
    <App />
  </StrictMode>
)

// Bun's HMR requires direct access to import.meta.hot.data — indirection
// through a local variable breaks its static analysis.
// https://bun.com/docs/bundler/hot-reloading#import-meta-hot-data
;(import.meta.hot.data.root ??= createRoot(elem)).render(app)
