# KidGuard AI Assistant

FastAPI Web Service called only by `kidguard-api`. It retains Gemini for text answers and provides self-hosted speech-to-text and text-to-speech. It has no PostgreSQL credentials and never authorizes child IDs; Node authenticates, applies role and child rules, and supplies only bounded authorized context to `/v1/answer`.

## Render Web Service

- Service name: `kidguard-ai-assistant`
- Build: `pip install -r requirements.txt && python download_models.py`
- Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check: `/health`
- Required secrets: `GEMINI_API_KEY`, `AI_ASSISTANT_SHARED_SECRET`
- Optional: `GEMINI_MODEL` (default `gemini-3.5-flash-lite`), `WHISPER_MODEL` (build prefetch currently targets `tiny`), `WHISPER_COMPUTE_TYPE=int8`, `WHISPER_CPU_THREADS=2`, `PIPER_VOICE_DIR` (defaults to `models/piper` in the service checkout)

Set the identical random `AI_ASSISTANT_SHARED_SECRET` on Python and Node. Set `AI_ASSISTANT_HOST=https://kidguard-ai-assistant.onrender.com` on Node. Keep Gemini and shared-secret values in Render environment settings only. Never add them to Flutter.

Node calls `/v1/answer`, `/v1/transcribe`, and `/v1/synthesize` with `X-KidGuard-AI-Secret`. `/v1/transcribe` accepts multipart WAV up to 8 MB and 90 seconds; it returns transcript text only. Whisper tiny runs multilingual on CPU/int8; English and Swahili language codes are accepted, with optional automatic detection. `/v1/synthesize` accepts at most 3,000 characters and returns WAV from Piper. The current voice set is Swahili `sw_CD-lanfrica-medium` plus English `en_US-hfc_female-medium` and `en_US-hfc_male-medium`. Piper's published voice catalogue only lists one Swahili voice, so the English gender selector does not create separate male/female Kiswahili voices. Review each model card and license before commercial release.

`download_models.py` fetches model weights into the build image. The models require a few hundred MB of build/image storage. Render's `starter` web plan has 0.5 CPU and 512 MB RAM; this has not been load-tested and is tight for predictable inference. Render's `standard` plan is 1 CPU and 2 GB RAM and is the recommended minimum for piloting Voice Mode. Benchmark request latency, memory and concurrency after deployment; do not treat `/health` as an inference readiness check. CPU performance and transcription accuracy vary with audio quality/accent; Whisper tiny is the smallest multilingual option and is less accurate than larger Whisper models.

Model processing is serialized per Python worker to reduce memory spikes. Uploaded bytes stay transient in the request and are not written as audio files. Raw microphone audio is not sent to Gemini; Node receives transcript text and passes it through the existing authorized chat path. Gemini chat retains its existing bounded-context and four-request provider concurrency controls.

## Local development

Install Python dependencies with `pip install -r requirements.txt`. Run `python download_models.py` to fetch the model weights, set the required Gemini/shared-secret environment values, and start `uvicorn main:app --host 127.0.0.1 --port 8001`. Run tests with `python -m unittest -v`. Endpoint tests mock model inference; run an actual microphone sample through STT/TTS after downloading weights to validate local machine performance.
