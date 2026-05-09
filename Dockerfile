FROM python:3.11-slim

RUN useradd -m -u 1000 user
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Install crewai and all main deps (openai pinned to crewai's requirement)
RUN pip install --no-cache-dir \
    "crewai==1.14.4" \
    "crewai-tools==1.14.4" \
    "gradio==6.14.0" \
    "httpx>=0.27.0" \
    "python-dotenv>=1.0.0" \
    "rich>=13.0.0" \
    "openai>=2.30.0,<3"

# Pre-install litellm's runtime deps so --no-deps litellm still works
RUN pip install --no-cache-dir \
    "tiktoken>=0.7.0" \
    "importlib-metadata==8.5.0" \
    "tokenizers>=0.15" \
    "aiohttp>=3.9" \
    "pydantic>=2.0"

# Install litellm without dep resolution — bypasses the openai==2.24.0 pin
# crewai needs litellm for model routing; openai 2.30+ is runtime-compatible
RUN pip install --no-cache-dir --no-deps "litellm==1.83.14"

COPY --chown=user:user . .

USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

EXPOSE 7860
CMD ["python", "app.py"]
