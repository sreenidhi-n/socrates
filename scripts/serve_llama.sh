#!/bin/bash
# Serve Llama via vLLM on AMD Developer Cloud
# Uses the pre-installed vLLM Docker image on the GPU droplet

set -euo pipefail

MODEL="${LLAMA_MODEL:-meta-llama/Llama-3.2-8B-Instruct}"
PORT="${LLAMA_PORT:-8000}"
API_KEY="${VLLM_API_KEY:-socrates-key}"
MODEL_NAME="${LLAMA_MODEL_NAME:-llama}"

echo "🏛️ Starting Llama: $MODEL on port $PORT"

# Stop existing container if running
docker stop llama 2>/dev/null || true
docker rm llama 2>/dev/null || true

docker run -d --name llama \
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

echo "✅ Llama serving on port $PORT"
echo "   Test: curl http://localhost:$PORT/v1/models -H 'Authorization: Bearer $API_KEY'"

# For demo day, switch to 70B:
# LLAMA_MODEL=meta-llama/Llama-3.3-70B-Instruct ./scripts/serve_llama.sh
