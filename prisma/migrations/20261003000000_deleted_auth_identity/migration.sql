-- Store only a SHA-256 digest so deleted accounts cannot be recreated by identity sync.
CREATE TABLE "DeletedAuthIdentity" (
    "firebaseUidHash" TEXT NOT NULL,
    "deletedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "DeletedAuthIdentity_pkey" PRIMARY KEY ("firebaseUidHash")
);
