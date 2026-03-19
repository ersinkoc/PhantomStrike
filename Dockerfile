# --- Build Stage ---
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build server binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/ersinkoc/phantomstrike/internal/pkg/version.Version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /phantomstrike ./cmd/server

# --- Runtime Stage ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata docker-cli

WORKDIR /app

COPY --from=builder /phantomstrike /app/phantomstrike
COPY --from=builder /build/config.yaml /app/config.yaml
COPY --from=builder /build/migrations /app/migrations
COPY --from=builder /build/tools /app/tools
COPY --from=builder /build/roles /app/roles
COPY --from=builder /build/skills /app/skills
COPY --from=builder /build/knowledge /app/knowledge

RUN mkdir -p /data/artifacts /data/catalog

EXPOSE 18090 18091

ENTRYPOINT ["/app/phantomstrike"]
