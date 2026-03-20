#!/bin/bash
# Test which tools are available and can run
cd "$(dirname "$0")/.."

PULLED=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null)
GOOD=0
BAD=0
ALLINONE=0
BAD_LIST=""

for f in $(find tools -name "*.yaml" | sort); do
    NAME=$(grep "^name:" "$f" | head -1 | awk '{print $2}' | tr -d '"')
    IMG=$(grep "image:" "$f" | head -1 | awk '{print $2}' | tr -d '"')
    CMD=$(grep "^command:" "$f" | head -1 | awk '{print $2}' | tr -d '"')

    [ -z "$NAME" ] && continue

    # Check if image is fake (phantomstrike/, kalilinux/, kali/, or empty)
    FAKE=false
    if [ -z "$IMG" ]; then
        FAKE=true
    elif echo "$IMG" | grep -qE "^phantomstrike/|^kalilinux/|^kali/"; then
        FAKE=true
    fi

    if [ "$FAKE" = "true" ]; then
        # Check if command exists in all-in-one image
        if docker run --rm phantomstrike-tools:latest which "$CMD" > /dev/null 2>&1; then
            ALLINONE=$((ALLINONE+1))
        else
            BAD=$((BAD+1))
            BAD_LIST="$BAD_LIST\n  $NAME ($CMD)"
        fi
    else
        # Check if the specific image is pulled
        IMG_BASE=$(echo "$IMG" | cut -d: -f1)
        if echo "$PULLED" | grep -q "$IMG_BASE"; then
            GOOD=$((GOOD+1))
        else
            # Try all-in-one as fallback
            if docker run --rm phantomstrike-tools:latest which "$CMD" > /dev/null 2>&1; then
                ALLINONE=$((ALLINONE+1))
            else
                BAD=$((BAD+1))
                BAD_LIST="$BAD_LIST\n  $NAME ($CMD, image: $IMG)"
            fi
        fi
    fi
done

echo ""
echo "=== TOOL AVAILABILITY REPORT ==="
echo "✅ Own Docker image (pulled): $GOOD"
echo "✅ All-in-one image (phantomstrike-tools): $ALLINONE"
echo "❌ Not available: $BAD"
echo "Total: $((GOOD+ALLINONE+BAD))"
echo ""
if [ $BAD -gt 0 ]; then
    echo "Missing tools:"
    echo -e "$BAD_LIST"
fi
