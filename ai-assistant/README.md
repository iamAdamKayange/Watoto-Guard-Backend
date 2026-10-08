# KidGuard AI Assistant

FastAPI Web Service used by the KidGuard Node backend. It receives already-authorized, bounded context from Node and does not connect to PostgreSQL.

## Deploy on Render

Deploy this repository as a **Web Service** named `kidguard-ai-assistant`.

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`
- Required environment variables: `GEMINI_API_KEY` and `AI_ASSISTANT_SHARED_SECRET`
- Optional: `GEMINI_MODEL` (defaults to `gemini-3.5-flash-lite`)

Set `AI_ASSISTANT_SHARED_SECRET` to the same random value on this service and `kidguard-api`. Set `AI_ASSISTANT_HOST=https://kidguard-ai-assistant.onrender.com` on `kidguard-api`. Keep secrets in Render environment settings; do not put them in Flutter or commit them to Git.

The public health endpoint is `https://kidguard-ai-assistant.onrender.com/health`. Node sends authenticated requests to `/v1/answer` using the `X-KidGuard-AI-Secret` header.

## Local development

Install dependencies with `pip install -r requirements.txt`, configure `GEMINI_API_KEY` and a 32-byte-or-longer `AI_ASSISTANT_SHARED_SECRET`, then run `uvicorn main:app --host 127.0.0.1 --port 8001`.

Run unit tests with `python -m unittest -v`.
