"""SOCrates configuration — model endpoints, API keys, and settings."""

import os

from dotenv import load_dotenv

load_dotenv()


# === vLLM Model Endpoints ===
LLAMA_BASE_URL: str = os.getenv("LLAMA_BASE_URL", "http://localhost:8000/v1")
QWEN_BASE_URL: str = os.getenv("QWEN_BASE_URL", "http://localhost:8090/v1")
VLLM_API_KEY: str = os.getenv("VLLM_API_KEY", "no-key")

LLAMA_MODEL_NAME: str = os.getenv("LLAMA_MODEL_NAME", "llama3.3:70b-instruct-q8_0")
QWEN_MODEL_NAME: str = os.getenv("QWEN_MODEL_NAME", "qwen2.5:72b-instruct-q4_K_M")

# === NVD API ===
NVD_API_KEY: str | None = os.getenv("NVD_API_KEY") or None
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# === MITRE ATT&CK ===
MITRE_DATA_PATH: str = os.path.join(os.path.dirname(__file__), "data", "attack.json")

# === Output ===
OUTPUT_DIR: str = os.path.join(os.path.dirname(__file__), "output")
