ALTER TABLE "Notification"
  ADD COLUMN "priority" TEXT NOT NULL DEFAULT 'NORMAL',
  ADD COLUMN "voiceEnabled" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "requiresVoiceAlert" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "voiceCategory" TEXT NOT NULL DEFAULT 'GENERAL';

CREATE TABLE "AIGuardianSettings" (
  "userId" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT false,
  "voiceEnabled" BOOLEAN NOT NULL DEFAULT true,
  "voiceNotificationsEnabled" BOOLEAN NOT NULL DEFAULT true,
  "highAlertsEnabled" BOOLEAN NOT NULL DEFAULT false,
  "criticalAlertsEnabled" BOOLEAN NOT NULL DEFAULT true,
  "normalNotificationsEnabled" BOOLEAN NOT NULL DEFAULT false,
  "schoolNotificationsEnabled" BOOLEAN NOT NULL DEFAULT false,
  "homeworkNotificationsEnabled" BOOLEAN NOT NULL DEFAULT false,
  "behaviorAlertsEnabled" BOOLEAN NOT NULL DEFAULT true,
  "safetyAlertsEnabled" BOOLEAN NOT NULL DEFAULT true,
  "language" TEXT NOT NULL DEFAULT 'sw',
  "voiceCategories" JSONB NOT NULL DEFAULT '{}',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AIGuardianSettings_pkey" PRIMARY KEY ("userId"),
  CONSTRAINT "AIGuardianSettings_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "AIGuardianRateLimitBucket" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "bucketStart" TIMESTAMP(3) NOT NULL,
  "requests" INTEGER NOT NULL DEFAULT 0,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AIGuardianRateLimitBucket_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AIGuardianRateLimitBucket_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "AIGuardianRateLimitBucket_userId_bucketStart_key" ON "AIGuardianRateLimitBucket"("userId", "bucketStart");
CREATE INDEX "AIGuardianRateLimitBucket_bucketStart_idx" ON "AIGuardianRateLimitBucket"("bucketStart");
