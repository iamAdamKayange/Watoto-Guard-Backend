-- New opt-in GPS reports have a short retention policy. NULL keeps legacy
-- location records outside automated deletion until they receive a separate review.
ALTER TABLE "DeviceLocation" ADD COLUMN "retentionClass" TEXT;
