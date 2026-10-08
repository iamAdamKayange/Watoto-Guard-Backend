# KidGuard AI Assistant

Private FastAPI service used by the KidGuard Node backend. It receives already-authorized, bounded context from Node and does not connect to PostgreSQL.

## Deploy on Render

Create a **Private Service** from this repository in the same Render region as `kidguard-api`.

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`
- Required environment variables: `GEMINI_API_KEY` and `AI_ASSISTANT_SHARED_SECRET`
- Optional: `GEMINI_MODEL` (defaults to `gemini-3.5-flash-lite`)

Set `AI_ASSISTANT_SHARED_SECRET` to the same random value on this service and the Node backend. Keep both secrets in Render environment settings; do not put them in Flutter or commit them to Git.

After deployment, set `AI_ASSISTANT_HOST` on `kidguard-api` to this service's internal `host:port` address, and set the same shared secret there. The health endpoint is private and should be checked from the Render private network.

## Local development

Install dependencies with `pip install -r requirements.txt`, configure `GEMINI_API_KEY` and a 32-byte-or-longer `AI_ASSISTANT_SHARED_SECRET`, then run `uvicorn main:app --host 127.0.0.1 --port 8001`.

Run unit tests with `python -m unittest -v`.
