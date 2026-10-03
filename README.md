# KidGuard API

Node.js, Express, TypeScript, Prisma, and PostgreSQL API for Render. PostgreSQL owns KidGuard accounts and application records. Firebase Admin is retained at runtime for FCM delivery; Firestore is used only by the one-time import utility. Notification records are committed to PostgreSQL before FCM delivery is attempted.

## Local setup

1. Copy `.env.example` to `.env`, set `DATABASE_URL`, then configure Firebase Admin with either `FIREBASE_SERVICE_ACCOUNT_JSON` (the full service account JSON) or all three split variables: `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, and `FIREBASE_PRIVATE_KEY`.
2. Run `npm install`, `npm run prisma:generate`, `npx prisma migrate deploy`, `npm run build`, then `npm start`.
3. The service health endpoint is `GET /health`.

Private routes use seven-day, signed API sessions backed by the `AUTH_TOKEN_SECRET` setting and re-check the user's active and school status on each request. Passwords are scrypt-hashed in PostgreSQL. Public parent registration requires a six-digit email code at `/api/auth/email-otp/request` and `/verify`; codes expire after ten minutes, allow five attempts, and enforce a 60-second resend cooldown with a five-per-hour email limit. `/api/auth/migrate-password` lets an imported legacy account set a PostgreSQL password after OTP verification. Google sign-in is verified by the backend using `GOOGLE_CLIENT_IDS`. School administrators and teachers receive scoped roles by claiming one-time email invitations.

Notification routes: `GET /api/notifications`, `GET /api/notifications/unread-count`, `PATCH /api/notifications/:id/read`, `PATCH /api/notifications/read-all`, and authorized `POST /api/notifications`. Read APIs scope every query to the authenticated database identity. Preferences are available at `/api/notifications/preferences`. Device token registration is `POST /api/devices/push-token`; child pairing uses `POST /api/device-links` to issue a one-use QR token. The child device signs into the PostgreSQL API with the authorized adult's email/password over HTTPS before redeeming the QR token; credentials are never placed in the QR code. Pairing tokens are hashed in PostgreSQL and consumed atomically. Device activity reports use `POST /api/device-events` with a per-device secret; PostgreSQL validates it and saves the event and any resulting notification before FCM delivery. Daily usage summaries are generated from PostgreSQL activity records.

Configure `RESEND_API_KEY`, `RESEND_FROM_EMAIL` (on a verified Resend domain), a long random `OTP_HASH_SECRET`, and the Google OAuth client IDs in the backend environment. Keep these server-only; do not add them to Flutter or `--dart-define`. Render creates `AUTH_TOKEN_SECRET` and runs Prisma migrations before starting the API.

`POST /api/children` registers child records without creating child accounts. `GET /api/children` returns only the authenticated user's permitted scope. Admin school/class routes and `/api/admin/children/:childId/teachers` enforce the assigned school at the API layer.

## Existing Firestore data import

The importer is idempotent. It migrates schools and classes, authenticated user roles, child profiles and parent/teacher relationships, devices and registration credentials, push tokens, notification history and read state. Unsupported top-level collections and unclassified users are preserved in `LegacyRecord` instead of being discarded.

After setting the Firebase Admin credentials and target `DATABASE_URL`, run a read-only inventory first:

```bash
npm run migrate:firestore -- --dry-run
```

Then back up both databases and import Firestore application records and Firebase Auth identities. These are copy-only operations; they never delete data in Firebase:

```bash
npm run prisma:migrate:deploy
npm run migrate:firestore
npm run migrate:firebase-auth
```

Neither importer deletes nor modifies Firebase records. Firestore collections without a relational model are copied into PostgreSQL `LegacyRecord` JSON rows, which the admin console can inspect. Confirm account roles, relationships, and import counts before decommissioning Firestore. Do not disable the old Firestore copy until all active app screens have been switched to PostgreSQL-backed APIs.

## Render

Use `render.yaml` at the repository root. Configure `FIREBASE_SERVICE_ACCOUNT_JSON` for FCM, `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `OTP_HASH_SECRET`, and `GOOGLE_CLIENT_IDS`, and link `DATABASE_URL` to Render PostgreSQL. Keep secrets in Render environment settings. The start command runs Prisma production migrations before launching the API. The Flutter base URL can be set with `--dart-define=KIDGUARD_API_BASE_URL=https://<your-render-service>.onrender.com`.

## School onboarding

School leaders can submit `POST /api/school-access-requests` without registering or completing email OTP. A global platform administrator (`ADMIN` with no `schoolId`) reviews requests in the app. Approval creates the school and sends the principal a one-time invitation code. The principal claims the invitation in the app to create a school-scoped `ADMIN` account; the invitation proves access to the requested email and expires after seven days. A school administrator can invite teachers with `POST /api/admin/school-invitations`; teachers claim the same way and receive the `TEACHER` role for that school. Student records remain managed through `/api/children` and are scoped to the school.

Invitation email delivery uses `RESEND_API_KEY` and `RESEND_FROM_EMAIL`. Set these in Render and use a sender address verified in Resend. The public school request itself does not depend on Resend or OTP. The schema migration is applied by `npm run start:render`.

Existing Firestore application data and the legacy Firebase Functions worker are left in place for staged migration. Do not deploy the legacy Firestore notification worker as the history backend; migrate its event producers to the API before disabling it. Runtime authentication and the admin website no longer use Firebase Authentication. FCM remains on Firebase.
