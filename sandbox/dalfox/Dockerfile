# Build stage
FROM golang:1.23-alpine AS builder

# Install DalFox
RUN go install -v github.com/hahwul/dalfox/v2@latest

# Runtime stage
FROM alpine:3.20

# Security: Non-root user
RUN addgroup -g 1000 -S phantom && \
    adduser -u 1000 -S phantom -G phantom

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/dalfox /usr/local/bin/dalfox

RUN mkdir -p /tmp/output && chown phantom:phantom /tmp/output

USER phantom

VOLUME ["/tmp"]

ENTRYPOINT ["dalfox"]
