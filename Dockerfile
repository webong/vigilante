# syntax=docker/dockerfile:1
# Build context must include the sibling ext/ checkout (go.mod uses local
# replace directives to ../ext). Build from the PARENT directory:
#
#   docker build -f vigilante/Dockerfile -t vigilante:latest .
#
# (or run from the parent: docker build -f vigilante/Dockerfile . )
FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
# Copy the whole workspace: vigilante/ + ext/ (replace directives need ext).
COPY vigilante/ ./vigilante/
COPY ext/ ./ext/
WORKDIR /src/vigilante
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vigilante ./cmd/vigilante

FROM alpine:3.20
RUN apk add --no-cache ca-certificates git iptables nftables \
    && adduser -D -H vigilante
COPY --from=build /out/vigilante /usr/local/bin/vigilante
COPY vigilante/deploy/vigilante.json.example /etc/vigilante/vigilante.json

# Data port (HTTP tap) and admin surface (healthz/metrics/obs).
EXPOSE 8080
USER vigilante
ENTRYPOINT ["/usr/local/bin/vigilante"]
CMD ["-config", "/etc/vigilante/vigilante.json"]