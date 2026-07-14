# WatotoGuard Render Notification Worker

This service runs on Render and replaces Firebase Cloud Functions for push delivery.

## Render setup

Create a new Render Web Service from this GitHub repo, or use the included `render.yaml`.

Required environment variables:

- `FIREBASE_PROJECT_ID`: `watotoguard`
- `FIREBASE_SERVICE_ACCOUNT_JSON`: full Firebase service account JSON on one line
- `LISTENER_LOOKBACK_MINUTES`: `120`

Build command:

```bash
npm install
```

Start command:

```bash
npm start
```

Health check path:

```text
/health
```

## Firebase service account

Firebase Console -> Project settings -> Service accounts -> Generate new private key.

Copy the JSON content and paste it into Render as `FIREBASE_SERVICE_ACCOUNT_JSON`.
Do not commit the JSON file to GitHub.
