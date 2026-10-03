CREATE TABLE "EmailChangeVerification" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "otpHash" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "sendsInWindow" INTEGER NOT NULL DEFAULT 0,
    "sendWindowStartedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sentAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "EmailChangeVerification_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "EmailChangeVerification_userId_key" ON "EmailChangeVerification"("userId");
CREATE UNIQUE INDEX "EmailChangeVerification_email_key" ON "EmailChangeVerification"("email");
CREATE INDEX "EmailChangeVerification_expiresAt_idx" ON "EmailChangeVerification"("expiresAt");
ALTER TABLE "EmailChangeVerification" ADD CONSTRAINT "EmailChangeVerification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
