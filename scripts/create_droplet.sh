#!/bin/bash
# Create AMD Developer Cloud GPU droplet via doctl
# Run this from the project root: ./scripts/create_droplet.sh

set -euo pipefail

# Load .env if present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env"
if [ -f "$ENV_FILE" ]; then
    set -a; source "$ENV_FILE"; set +a
fi

IMAGE="${AMD_DROPLET_IMAGE:-rocm-7-2-software}"
SIZE="${AMD_DROPLET_SIZE:-gpu-mi300x8-1536gb-devcloud}"
REGION="${AMD_DROPLET_REGION:-atl1}"
API_URL="${AMD_API_URL:-http://api.devcloud.amd.com/}"
DROPLET_NAME="${IMAGE}-${SIZE}-${REGION}"

echo "Creating droplet: $DROPLET_NAME"
echo "Image: $IMAGE | Size: $SIZE | Region: $REGION"
echo ""

doctl compute droplet create \
    --image "$IMAGE" \
    --size "$SIZE" \
    --region "$REGION" \
    --tag-names '' \
    --api-url "$API_URL" \
    "$DROPLET_NAME"

echo ""
echo "Waiting 15s for IP assignment..."
sleep 15

IP=$(doctl compute droplet list \
    --api-url "$API_URL" \
    --format "Name,PublicIPv4" \
    --no-header \
    | grep "$DROPLET_NAME" \
    | awk '{print $2}')

if [ -n "$IP" ] && [ "$IP" != "<nil>" ]; then
    echo "Droplet IP: $IP"
    echo ""
    echo "Updating .env with droplet IP..."
    sed -i '' \
        "s|LLAMA_BASE_URL=.*|LLAMA_BASE_URL=http://$IP:8000/v1|" \
        "$ENV_FILE"
    sed -i '' \
        "s|QWEN_BASE_URL=.*|QWEN_BASE_URL=http://$IP:8090/v1|" \
        "$ENV_FILE"
    echo "Done. .env updated:"
    echo "  LLAMA_BASE_URL=http://$IP:8000/v1"
    echo "  QWEN_BASE_URL=http://$IP:8090/v1"
    echo ""
    echo "Next: add your HF_TOKEN to .env, then SSH in and run the model servers:"
    echo "  ssh root@$IP"
    echo "  ./scripts/setup_cloud.sh"
    echo "  ./scripts/serve_llama.sh"
    echo "  ./scripts/serve_qwen.sh"
else
    echo "IP not assigned yet. Run this to check:"
    echo "  doctl compute droplet list --api-url $API_URL"
    echo ""
    echo "Then manually update .env:"
    echo "  LLAMA_BASE_URL=http://<ip>:8000/v1"
    echo "  QWEN_BASE_URL=http://<ip>:8090/v1"
fi
