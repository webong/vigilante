import { queryOptions } from "@tanstack/react-query"
import { type ActorFilter, api } from "@/api"

export const sessionQuery = queryOptions({
  queryKey: ["session"],
  queryFn: api.session,
  staleTime: 30_000,
})

export const overviewQuery = queryOptions({
  queryKey: ["overview"],
  queryFn: api.overview,
  refetchInterval: 5_000,
})

export const actorsQuery = (filter: ActorFilter) =>
  queryOptions({
    queryKey: ["actors", filter],
    queryFn: () => api.actors(filter),
    refetchInterval: 5_000,
  })

export const actorQuery = (id: number) =>
  queryOptions({
    queryKey: ["actor", id],
    queryFn: () => api.actor(id),
    refetchInterval: 5_000,
  })

export const decisionsQuery = queryOptions({
  queryKey: ["decisions"],
  queryFn: api.decisions,
  refetchInterval: 5_000,
})

export const egressQuery = queryOptions({
  queryKey: ["egress"],
  queryFn: api.egress,
  refetchInterval: 10_000,
})

export const sensorsQuery = queryOptions({
  queryKey: ["sensors"],
  queryFn: api.sensors,
  refetchInterval: 5_000,
})
