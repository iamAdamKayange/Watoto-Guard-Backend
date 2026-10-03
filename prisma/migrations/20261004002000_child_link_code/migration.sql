ALTER TABLE "Child" ADD COLUMN "linkCode" TEXT;
CREATE UNIQUE INDEX "Child_linkCode_key" ON "Child"("linkCode");
