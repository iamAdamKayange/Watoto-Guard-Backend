CREATE TABLE "ChildSafetyTerm" (
    "id" TEXT NOT NULL,
    "childId" TEXT NOT NULL,
    "createdById" TEXT NOT NULL,
    "term" TEXT NOT NULL,
    "normalizedTerm" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ChildSafetyTerm_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ChildSafetyTerm_childId_normalizedTerm_key" ON "ChildSafetyTerm"("childId", "normalizedTerm");
CREATE INDEX "ChildSafetyTerm_childId_enabled_idx" ON "ChildSafetyTerm"("childId", "enabled");

ALTER TABLE "ChildSafetyTerm" ADD CONSTRAINT "ChildSafetyTerm_childId_fkey" FOREIGN KEY ("childId") REFERENCES "Child"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ChildSafetyTerm" ADD CONSTRAINT "ChildSafetyTerm_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
