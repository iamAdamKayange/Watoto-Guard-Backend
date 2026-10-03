# KidGuard API

Node.js, Express, TypeScript, Prisma, and PostgreSQL API for Render. Firebase Authentication remains the identity provider and FCM remains the push transport. Notification records are committed to PostgreSQL before FCM delivery is attempted.

## Local setup

1. Copy `.env.example` to `.env`, set `DATABASE_URL`, then configure Firebase Admin with either `FIREBASE_SERVICE_ACCOUNT_JSON` (the full service account JSON) or all three split variables: `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, and `FIREBASE_PRIVATE_KEY`.
2. Run `npm install`, `npm run prisma:generate`, `npx prisma migrate deploy`, `npm run build`, then `npm start`.
3. The service health endpoint is `GET /health`.

Firebase ID tokens are verified for all private routes. `/api/auth/sync` only creates a `PARENT` identity. Create ADMIN/TEACHER users and their school/child relationships through a trusted provisioning process; clients cannot select privileged roles.

Notification routes: `GET /api/notifications`, `GET /api/notifications/unread-count`, `PATCH /api/notifications/:id/read`, `PATCH /api/notifications/read-all`, and authorized `POST /api/notifications`. Read APIs scope every query to the authenticated database identity. Preferences are available at `/api/notifications/preferences`. Device token registration is `POST /api/devices/push-token`; child device pairing uses the authenticated `POST /api/device-links` endpoint and one-use unauthenticated `POST /api/device-links/register` endpoint. The pairing token is hashed in PostgreSQL, expires within an hour, and is consumed atomically. Device activity reports use `POST /api/device-events` with a per-device secret; PostgreSQL validates it and saves the event and any resulting notification before FCM delivery. Daily usage summaries are generated from PostgreSQL activity records.

`POST /api/children` registers child records without creating child accounts. `GET /api/children` returns only the authenticated user's permitted scope. Admin school/class routes and `/api/admin/children/:childId/teachers` enforce the assigned school at the API layer.

## Existing Firestore data import

The importer is idempotent. It migrates schools and classes, authenticated user roles, child profiles and parent/teacher relationships, devices and registration credentials, push tokens, notification history and read state. Unsupported top-level collections and unclassified users are preserved in `LegacyRecord` instead of being discarded.

After setting the Firebase Admin credentials and target `DATABASE_URL`, run a read-only inventory first:

```bash
npm run migrate:firestore -- --dry-run
```

Then back up both databases and run the import:

```bash
npm run prisma:migrate:deploy
npm run migrate:firestore
```

The importer does not delete or modify Firestore records. Review import counts and confirm existing ADMIN/TEACHER roles and child relationships in PostgreSQL before switching remaining providers or disabling Firestore event mirroring. Legacy academic and other collection records are preserved as JSON while their screens continue to use the existing Firestore implementation.

## Render

Use `render.yaml` at the repository root. Set `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY`, and link `DATABASE_URL` to the Render PostgreSQL instance. Keep secrets in Render environment settings. The start command runs Prisma production migrations before launching the API. The Flutter base URL can be set with `--dart-define=KIDGUARD_API_BASE_URL=https://<your-render-service>.onrender.com`.

Existing Firestore application data and the legacy Firebase Functions worker are left in place for staged migration. Do not deploy the legacy Firestore notification worker as the history backend; migrate its event producers to the API before disabling it. Firestore notification history is no longer queried by the Flutter notification provider.
