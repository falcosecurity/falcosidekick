import js from "@eslint/js"
import globals from "globals"
import reactHooks from "eslint-plugin-react-hooks"
import tseslint from "typescript-eslint"
import { defineConfig, globalIgnores } from "eslint/config"

const restrictedImports = {
  paths: [
    {
      name: "axios",
      message:
        "Import from '@/lib/api-client' instead. Direct axios usage is forbidden outside the API boundary.",
    },
  ],
}

export default defineConfig([
  globalIgnores(["dist", "node_modules", "src/components/ui/**"]),
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, tseslint.configs.recommended, reactHooks.configs.flat.recommended],
    languageOptions: {
      ecmaVersion: 2020,
      globals: { ...globals.browser, Bun: "readonly" },
    },
    rules: {
      "no-restricted-imports": ["error", restrictedImports],
      "no-restricted-globals": [
        "error",
        {
          name: "fetch",
          message:
            "Use '@/lib/api-client' for HTTP calls. Direct fetch is allowed only inside the API boundary and the Bun dev server (src/index.ts).",
        },
      ],
    },
  },
  {
    files: ["src/lib/api-client.ts", "src/index.ts"],
    rules: {
      "no-restricted-imports": "off",
      "no-restricted-globals": "off",
    },
  },
  {
    files: ["**/*.test.{ts,tsx}"],
    rules: {
      "no-restricted-imports": "off",
      "no-restricted-globals": "off",
    },
  },
])
