CREATE TYPE "SchoolRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

CREATE TABLE "SchoolAccessRequest" (
    "id" TEXT NOT NULL,
    "contactName" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "phone" TEXT NOT NULL,
    "position" TEXT NOT NULL,
    "schoolName" TEXT NOT NULL,
    "schoolAddress" TEXT NOT NULL,
    "website" TEXT,
    "studentCount" INTEGER,
    "message" TEXT,
    "status" "SchoolRequestStatus" NOT NULL DEFAULT 'PENDING',
    "schoolId" TEXT,
    "reviewerId" TEXT,
    "reviewNote" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SchoolAccessRequest_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SchoolInvitation" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "phone" TEXT,
    "role" "Role" NOT NULL,
    "schoolId" TEXT NOT NULL,
    "creatorId" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "SchoolInvitation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "SchoolAccessRequest_schoolId_key" ON "SchoolAccessRequest"("schoolId");
CREATE INDEX "SchoolAccessRequest_status_createdAt_idx" ON "SchoolAccessRequest"("status", "createdAt");
CREATE INDEX "SchoolAccessRequest_email_createdAt_idx" ON "SchoolAccessRequest"("email", "createdAt");
CREATE UNIQUE INDEX "SchoolInvitation_tokenHash_key" ON "SchoolInvitation"("tokenHash");
CREATE INDEX "SchoolInvitation_schoolId_email_usedAt_idx" ON "SchoolInvitation"("schoolId", "email", "usedAt");
CREATE INDEX "SchoolInvitation_expiresAt_idx" ON "SchoolInvitation"("expiresAt");

ALTER TABLE "SchoolAccessRequest"
ADD CONSTRAINT "SchoolAccessRequest_schoolId_fkey"
FOREIGN KEY ("schoolId") REFERENCES "School"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "SchoolAccessRequest"
ADD CONSTRAINT "SchoolAccessRequest_reviewerId_fkey"
FOREIGN KEY ("reviewerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "SchoolInvitation"
ADD CONSTRAINT "SchoolInvitation_schoolId_fkey"
FOREIGN KEY ("schoolId") REFERENCES "School"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "SchoolInvitation"
ADD CONSTRAINT "SchoolInvitation_creatorId_fkey"
FOREIGN KEY ("creatorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
