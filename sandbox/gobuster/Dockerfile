# Build stage
FROM golang:1.23-alpine AS builder

# Install gobuster
RUN go install -v github.com/OJ/gobuster/v3@latest

# Runtime stage
FROM alpine:3.20

# Security: Non-root user
RUN addgroup -g 1000 -S phantom && \
    adduser -u 1000 -S phantom -G phantom

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/gobuster /usr/local/bin/gobuster

RUN mkdir -p /tmp/output && chown phantom:phantom /tmp/output

USER phantom

VOLUME ["/tmp"]

ENTRYPOINT ["gobuster"]
