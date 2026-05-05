#!/bin/bash
# Serve Qwen via vLLM on AMD Developer Cloud
# Second model instance for the Coroner agent

set -euo pipefail

MODEL="${QWEN_MODEL:-Qwen/Qwen3-8B}"
PORT="${QWEN_PORT:-8090}"
API_KEY="${VLLM_API_KEY:-socrates-key}"
MODEL_NAME="${QWEN_MODEL_NAME:-qwen}"

echo "🏛️ Starting Qwen: $MODEL on port $PORT"

# Stop existing container if running
docker stop qwen 2>/dev/null || true
docker rm qwen 2>/dev/null || true

docker run -d --name qwen \
    -p "$PORT:$PORT" \
    --ipc=host --network=host --privileged \
    --cap-add=CAP_SYS_ADMIN \
    --device=/dev/kfd --device=/dev/dri --device=/dev/mem \
    --group-add render \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -e HF_TOKEN="$HF_TOKEN" \
    vllm/vllm-openai:latest \
    --model "$MODEL" \
    --served-model-name "$MODEL_NAME" \
    --api-key "$API_KEY" \
    --port "$PORT"

echo "✅ Qwen serving on port $PORT"
echo "   Test: curl http://localhost:$PORT/v1/models -H 'Authorization: Bearer $API_KEY'"

# For demo day, switch to 72B:
# QWEN_MODEL=Qwen/Qwen3-72B ./scripts/serve_qwen.sh
