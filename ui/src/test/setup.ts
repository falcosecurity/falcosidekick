import { GlobalRegistrator } from "@happy-dom/global-registrator"
import "@testing-library/jest-dom"

GlobalRegistrator.register({ url: "http://localhost:5173" })
