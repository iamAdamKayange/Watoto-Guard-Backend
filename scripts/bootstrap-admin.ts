import "dotenv/config";
import { randomBytes, scryptSync } from "node:crypto";
import { PrismaClient, Role } from "@prisma/client";

const email = process.env.ADMIN_BOOTSTRAP_EMAIL?.trim().toLowerCase();
const password = process.env.ADMIN_BOOTSTRAP_PASSWORD;
const fullName = process.env.ADMIN_BOOTSTRAP_NAME?.trim() || "Adam Kayange";

if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  console.error("Set ADMIN_BOOTSTRAP_EMAIL to a valid email address.");
  process.exit(1);
}
if (!password || password.length < 10 || password.length > 128) {
  console.error("Set ADMIN_BOOTSTRAP_PASSWORD to a unique password between 10 and 128 characters.");
  process.exit(1);
}
if (fullName.length < 2 || fullName.length > 160) {
  console.error("ADMIN_BOOTSTRAP_NAME must be between 2 and 160 characters.");
  process.exit(1);
}

const salt = randomBytes(16).toString("base64url");
const passwordHash = `${salt}:${scryptSync(password, salt, 64).toString("base64url")}`;
const prisma = new PrismaClient();

try {
  const user = await prisma.user.upsert({
    where: { email },
    create: {
      firebaseUid: `pg_${randomBytes(20).toString("hex")}`,
      email,
      fullName,
      passwordHash,
      emailVerified: true,
      role: Role.ADMIN,
      schoolId: null,
      isActive: true,
    },
    update: {
      fullName,
      passwordHash,
      emailVerified: true,
      role: Role.ADMIN,
      schoolId: null,
      isActive: true,
    },
    select: { id: true, email: true, role: true },
  });
  await prisma.auditLog.create({
    data: {
      actorId: user.id,
      action: "auth.platform_admin_bootstrap",
      entityType: "user",
      entityId: user.id,
      details: { email: user.email },
    },
  });
  console.log(`Platform administrator is ready: ${user.email}`);
} catch (error) {
  console.error("Could not bootstrap the platform administrator.");
  console.error(error instanceof Error ? error.message : "Unknown database error");
  process.exitCode = 1;
} finally {
  await prisma.$disconnect();
}
