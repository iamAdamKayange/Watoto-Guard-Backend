import "dotenv/config";
import { cert, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { PrismaClient, Role } from "@prisma/client";

const dryRun = process.argv.includes("--dry-run");
const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) as { project_id?: string; client_email?: string; private_key?: string }
  : undefined;
const projectId = process.env.FIREBASE_PROJECT_ID || serviceAccount?.project_id;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL || serviceAccount?.client_email;
const privateKey = (process.env.FIREBASE_PRIVATE_KEY || serviceAccount?.private_key)?.replace(/\\n/g, "\n");
if (!projectId || !clientEmail || !privateKey) throw new Error("Set Firebase Admin credentials before importing accounts.");
if (!process.env.DATABASE_URL) throw new Error("Set DATABASE_URL to the PostgreSQL target before importing.");

const firebaseApp = initializeApp({ credential: cert({ projectId, clientEmail, privateKey }) }, "kidguard-auth-import");
const prisma = new PrismaClient();
const auth = getAuth(firebaseApp);

function roleOf(value: unknown): Role {
  const role = String(value ?? "").trim().toUpperCase();
  if (role === "ADMIN" || role === "TEACHER" || role === "PARENT") return role as Role;
  return Role.PARENT;
}

async function main() {
  let pageToken: string | undefined;
  let seen = 0;
  let matched = 0;
  let created = 0;
  let skipped = 0;
  do {
    const page = await auth.listUsers(1000, pageToken);
    for (const account of page.users) {
      seen++;
      if (!account.email) { skipped++; continue; }
      const email = account.email.trim().toLowerCase();
      const existing = await prisma.user.findFirst({ where: { OR: [{ firebaseUid: account.uid }, { email }] } });
      if (dryRun) {
        if (existing) matched++; else created++;
        continue;
      }
      if (existing) {
        await prisma.user.update({ where: { id: existing.id }, data: {
          email, emailVerified: account.emailVerified,
          fullName: existing.fullName || account.displayName || email,
          phone: existing.phone ?? account.phoneNumber,
        } });
        matched++;
      } else {
        await prisma.user.create({ data: {
          firebaseUid: account.uid,
          email,
          fullName: account.displayName || email,
          phone: account.phoneNumber,
          emailVerified: account.emailVerified,
          role: roleOf(account.customClaims?.role),
        } });
        created++;
      }
    }
    pageToken = page.pageToken;
  } while (pageToken);

  console.log(JSON.stringify({ dryRun, processed: seen, matched, created, skipped }, null, 2));
  if (dryRun) console.log("Dry run complete. No PostgreSQL rows were changed.");
  else console.log("Firebase Auth identities have been copied to PostgreSQL. Passwords were not copied; users set a PostgreSQL password using the email OTP migration flow.");
}

main().catch(error => { console.error("Firebase Auth import failed", error); process.exitCode = 1; }).finally(async () => { await prisma.$disconnect(); });
