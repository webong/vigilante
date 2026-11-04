import { createFileRoute } from "@tanstack/react-router"
import { VisitorDetail } from "@/components/visitor-detail"
import { VisitorPlaceholder } from "./visitors"

export const Route = createFileRoute("/_app/visitors/$actorId")({
  component: ActorDetailRoute,
})

function ActorDetailRoute() {
  const { actorId } = Route.useParams()
  const id = Number(actorId)
  if (!Number.isSafeInteger(id) || id <= 0) return <VisitorPlaceholder />
  return <VisitorDetail id={id} />
}
