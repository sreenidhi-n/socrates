#!/bin/bash
# SOCrates — AMD Developer Cloud Setup
# Run this after SSH-ing into your GPU droplet

set -euo pipefail

echo "🏛️ SOCrates Cloud Setup"
echo "========================"

# Check GPU is visible
echo "Checking GPU..."
rocm-smi || echo "⚠️  rocm-smi not found — GPU may not be properly configured"

# Set your HF token (needed for gated models like Llama)
if [ -z "${HF_TOKEN:-}" ]; then
    echo "⚠️  HF_TOKEN not set. Export it before running model containers."
    echo "   export HF_TOKEN=your-token-here"
fi

# Set vLLM API key
export VLLM_API_KEY="${VLLM_API_KEY:-socrates-key-$(date +%s)}"
echo "vLLM API Key: $VLLM_API_KEY"
echo "(Save this — you'll need it in .env)"

echo ""
echo "Setup complete. Now run:"
echo "  ./scripts/serve_llama.sh   # Start Llama on :8000"
echo "  ./scripts/serve_qwen.sh    # Start Qwen on :8090"
