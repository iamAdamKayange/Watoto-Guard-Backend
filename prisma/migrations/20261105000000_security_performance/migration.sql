-- Session revocation: bumping tokenVersion invalidates every previously issued API token.
ALTER TABLE "User" ADD COLUMN "tokenVersion" INTEGER NOT NULL DEFAULT 0;

-- Hot-path indexes for heartbeat lookups, stale-device alerts and record listing.
CREATE INDEX "DeviceActivityEvent_deviceId_type_createdAt_idx" ON "DeviceActivityEvent"("deviceId", "type", "createdAt");
CREATE INDEX "Notification_relatedEntity_relatedId_createdAt_idx" ON "Notification"("relatedEntity", "relatedId", "createdAt");
CREATE INDEX "LegacyRecord_collection_updatedAt_idx" ON "LegacyRecord"("collection", "updatedAt");
