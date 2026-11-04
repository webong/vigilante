import { createFileRoute } from "@tanstack/react-router"
import { VisitorPlaceholder } from "./visitors"

export const Route = createFileRoute("/_app/visitors/")({
  component: VisitorPlaceholder,
})
