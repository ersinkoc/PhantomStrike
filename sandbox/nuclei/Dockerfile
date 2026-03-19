# Build stage
FROM golang:1.23-alpine AS builder

# Install nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates

# Runtime stage
FROM alpine:3.20

# Security: Create non-root user
RUN addgroup -g 1000 -S phantom && \
    adduser -u 1000 -S phantom -G phantom

# Install runtime dependencies only
RUN apk add --no-cache ca-certificates git

# Copy nuclei binary
COPY --from=builder /go/bin/nuclei /usr/local/bin/nuclei

# Copy templates
COPY --from=builder /root/.config/nuclei /home/phantom/.config/nuclei
RUN chown -R phantom:phantom /home/phantom/.config

# Create tmp directory for output
RUN mkdir -p /tmp/output && chown phantom:phantom /tmp/output

# Switch to non-root user
USER phantom

# Security: Read-only filesystem
VOLUME ["/tmp"]

ENTRYPOINT ["nuclei"]
CMD ["-version"]
