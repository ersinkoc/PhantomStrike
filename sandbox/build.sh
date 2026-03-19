#!/bin/bash
set -e

REGISTRY=${REGISTRY:-"phantomstrike"}
TAG=${TAG:-"latest"}

echo "Building PhantomStrike sandbox images..."

for tool in nuclei nmap dalfox testssl gobuster; do
    echo "Building $tool..."
    docker build -t $REGISTRY/$tool:$tag $tool/ || exit 1
done

echo "All images built successfully!"
