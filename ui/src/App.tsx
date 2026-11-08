import { AppRouter } from "@/app/routes"
import { Providers } from "@/app/providers"

export function App() {
  return (
    <Providers>
      <AppRouter />
    </Providers>
  )
}

export default App
