# Build stage
FROM alpine:3.20 AS builder

RUN apk add --no-cache git bash openssl

WORKDIR /opt
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git

# Runtime stage
FROM alpine:3.20

# Security: Non-root user
RUN addgroup -g 1000 -S phantom && \
    adduser -u 1000 -S phantom -G phantom

RUN apk add --no-cache bash openssl

COPY --from=builder /opt/testssl.sh /opt/testssl.sh

RUN mkdir -p /tmp/output && chown phantom:phantom /tmp/output

USER phantom

WORKDIR /opt/testssl.sh

VOLUME ["/tmp"]

ENTRYPOINT ["./testssl.sh"]
