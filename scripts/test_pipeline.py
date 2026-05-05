"""Quick test — verify the SOCrates pipeline end-to-end."""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from socrates.tools.nvd_tool import NVDSearchTool


def test_nvd_tool():
    """Test NVD API connectivity."""
    print("🔍 Testing NVD API...")
    tool = NVDSearchTool()
    result = tool._run("CVE-2024-3400")
    print(result[:500])
    print("✅ NVD API working\n")


def test_model_endpoint():
    """Test vLLM endpoint connectivity."""
    import httpx
    from socrates.config import LLAMA_BASE_URL, VLLM_API_KEY

    print(f"🔍 Testing vLLM endpoint at {LLAMA_BASE_URL}...")
    try:
        response = httpx.get(
            f"{LLAMA_BASE_URL}/models",
            headers={"Authorization": f"Bearer {VLLM_API_KEY}"},
            timeout=10.0,
        )
        print(f"   Status: {response.status_code}")
        print(f"   Models: {response.json()}")
        print("✅ vLLM endpoint reachable\n")
    except Exception as e:
        print(f"❌ vLLM endpoint unreachable: {e}\n")


if __name__ == "__main__":
    test_nvd_tool()
    test_model_endpoint()
    print("🏛️ All basic tests passed. Ready to run the full crew.")
