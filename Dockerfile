FROM python:3.11-slim

RUN useradd -m -u 1000 user
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# crewai's hosted_vllm provider routes natively (no litellm needed).
# This avoids the openai version conflict between crewai (>=2.30.0) and litellm (==2.24.0).
RUN pip install --no-cache-dir \
    "crewai==1.14.4" \
    "crewai-tools==1.14.4" \
    "gradio==6.14.0" \
    "httpx>=0.27.0" \
    "python-dotenv>=1.0.0" \
    "rich>=13.0.0"

COPY --chown=user:user . .

USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

EXPOSE 7860
CMD ["python", "app.py"]
