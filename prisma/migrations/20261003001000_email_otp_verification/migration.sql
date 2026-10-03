ALTER TABLE "User"
ADD COLUMN "emailVerified" BOOLEAN NOT NULL DEFAULT false;

-- Existing provisioned accounts predate OTP and retain their current access.
UPDATE "User" SET "emailVerified" = true;

CREATE TABLE "EmailOtpVerification" (
    "email" TEXT NOT NULL,
    "otpHash" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "phone" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "sendsInWindow" INTEGER NOT NULL DEFAULT 0,
    "sendWindowStartedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sentAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "registrationExpiresAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "EmailOtpVerification_pkey" PRIMARY KEY ("email")
);

CREATE INDEX "EmailOtpVerification_expiresAt_idx" ON "EmailOtpVerification"("expiresAt");
