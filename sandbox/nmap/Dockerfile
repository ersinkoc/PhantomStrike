# Build stage
FROM alpine:3.20 AS builder

# Build nmap from source with minimal features
RUN apk add --no-cache build-base openssl-dev libpcap-dev lua-dev \
    && wget https://nmap.org/dist/nmap-7.94.tar.bz2 \
    && tar xjf nmap-7.94.tar.bz2 \
    && cd nmap-7.94 \
    && ./configure --without-zenmap --without-ncat --without-nping \
                   --without-nmap-update --with-libpcap=included \
                   --without-subversion --without-ndiff \
    && make -j$(nproc) \
    && make install

# Runtime stage
FROM alpine:3.20

# Security: Non-root user
RUN addgroup -g 1000 -S phantom && \
    adduser -u 1000 -S phantom -G phantom

# Minimal runtime deps
RUN apk add --no-cache libpcap libstdc++ lua5.4-libs

# Copy nmap binaries
COPY --from=builder /usr/local/bin/nmap /usr/local/bin/nmap
COPY --from=builder /usr/local/share/nmap /usr/local/share/nmap

# Create output directory
RUN mkdir -p /tmp/output && chown phantom:phantom /tmp/output

USER phantom

VOLUME ["/tmp"]

ENTRYPOINT ["nmap"]
