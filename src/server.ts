import "dotenv/config";
import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { Prisma, PrismaClient, Role } from "@prisma/client";
import { z } from "zod";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const prisma = new PrismaClient();
const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGINS?.split(",").filter(Boolean) ?? true }));
app.use(express.json({ limit: "256kb" }));

const firebaseServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) as { project_id?: string; client_email?: string; private_key?: string }
  : undefined;
const firebaseProjectId = process.env.FIREBASE_PROJECT_ID || firebaseServiceAccount?.project_id;
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL || firebaseServiceAccount?.client_email;
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY || firebaseServiceAccount?.private_key;

if (!getApps().length && firebaseProjectId && firebaseClientEmail && firebasePrivateKey) {
  initializeApp({ credential: cert({
    projectId: firebaseProjectId,
    clientEmail: firebaseClientEmail,
    privateKey: firebasePrivateKey.replace(/\\n/g, "\n"),
  }) });
}

type Principal = { id: string; firebaseUid: string; role: Role; schoolId: string | null; fullName: string; email: string };
declare global { namespace Express { interface Request { principal?: Principal } } }

function publicUser<T extends { id: string; firebaseUid: string }>(row: T) {
  const { id, firebaseUid: _firebaseUid, ...data } = row;
  return { ...data, id: row.firebaseUid, databaseId: id };
}

function asyncRoute(handler: (req: Request, res: Response) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction) => { void handler(req, res).catch(next); };
}

const authenticate = (req: Request, res: Response, next: NextFunction) => {
  void (async () => {
    if (!getApps().length) { res.status(503).json({ error: "Authentication service is not configured" }); return; }
    const token = req.header("authorization")?.match(/^Bearer (.+)$/i)?.[1];
    if (!token) { res.status(401).json({ error: "Bearer token required" }); return; }
    try {
      const decoded = await getAuth().verifyIdToken(token);
      const user = await prisma.user.findUnique({ where: { firebaseUid: decoded.uid } });
      if (!user || !user.isActive) { res.status(403).json({ error: "Account is not provisioned" }); return; }
      req.principal = user;
      next();
    } catch { res.status(401).json({ error: "Invalid or expired token" }); }
  })().catch(next);
};

function allow(...roles: Role[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.principal || !roles.includes(req.principal.role)) { res.status(403).json({ error: "Forbidden" }); return; }
    next();
  };
}

async function canAccessChild(user: Principal, childId: string) {
  if (user.role === Role.ADMIN) {
    const child = await prisma.child.findUnique({ where: { id: childId }, select: { schoolId: true } });
    return !!child && (!user.schoolId || child.schoolId === user.schoolId);
  }
  if (user.role === Role.PARENT) return !!await prisma.parentChild.findUnique({ where: { parentId_childId: { parentId: user.id, childId } } });
  return !!await prisma.teacherStudent.findUnique({ where: { teacherId_studentId: { teacherId: user.id, studentId: childId } } });
}

app.get("/", (_req, res) => res.json({
  name: "KidGuard API",
  status: "ok",
  health: "/health",
}));

app.get("/health", (_req, res) => res.json({ status: "ok", service: "kidguard-api" }));

app.get("/api/schools", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  const where: Prisma.SchoolWhereInput = user.role === Role.ADMIN
    ? { ...(user.schoolId ? { id: user.schoolId } : {}) }
    : user.role === Role.TEACHER
      ? { id: user.schoolId ?? "" }
      : { children: { some: { parents: { some: { parentId: user.id } } } } };
  const schools = await prisma.school.findMany({ where, orderBy: { name: "asc" } });
  res.json({ schools });
}));

app.post("/api/admin/schools", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const input = z.object({ id: z.string().optional(), name: z.string().trim().min(1).max(160), code: z.string().max(40).optional(), address: z.string().max(300).optional(), phone: z.string().max(40).optional(), email: z.string().email().optional(), website: z.string().url().optional(), logoUrl: z.string().url().optional(), description: z.string().max(2000).optional(), motto: z.string().max(300).optional(), principalName: z.string().max(160).optional(), settings: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if (req.principal!.schoolId && req.principal!.schoolId !== input.data.id) { res.status(403).json({ error: "Admin can manage only their assigned school" }); return; }
  const { id, ...data } = input.data;
  const school = id
    ? await prisma.school.upsert({ where: { id }, create: { id, ...data, settings: data.settings as Prisma.InputJsonValue }, update: { ...data, settings: data.settings as Prisma.InputJsonValue } })
    : await prisma.school.create({ data: { ...data, settings: data.settings as Prisma.InputJsonValue } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "school.upsert", entityType: "school", entityId: school.id } });
  res.status(201).json({ school });
}));

app.patch("/api/admin/schools/:schoolId", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const schoolId = req.params.schoolId.toString();
  if (req.principal!.schoolId && req.principal!.schoolId !== schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  const input = z.object({ name: z.string().trim().min(1).max(160).optional(), code: z.string().max(40).optional(), address: z.string().max(300).optional(), phone: z.string().max(40).optional(), email: z.string().email().optional(), website: z.string().url().optional(), logoUrl: z.string().url().optional(), description: z.string().max(2000).optional(), motto: z.string().max(300).optional(), principalName: z.string().max(160).optional(), isActive: z.boolean().optional(), settings: z.record(z.unknown()).optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const { settings, ...schoolFields } = input.data;
  const school = await prisma.school.update({ where: { id: schoolId }, data: { ...schoolFields, ...(settings ? { settings: settings as Prisma.InputJsonValue } : {}) } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "school.update", entityType: "school", entityId: school.id } });
  res.json({ school });
}));

app.get("/api/classes", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  const schoolId = typeof req.query.schoolId === "string" ? req.query.schoolId : user.schoolId;
  if (user.role === Role.ADMIN && (!user.schoolId || user.schoolId === schoolId)) {
    res.json({ classes: await prisma.schoolClass.findMany({ where: schoolId ? { schoolId } : {}, orderBy: { name: "asc" } }) }); return;
  }
  if (user.role === Role.TEACHER && user.schoolId && user.schoolId === schoolId) {
    res.json({ classes: await prisma.schoolClass.findMany({ where: { schoolId }, orderBy: { name: "asc" } }) }); return;
  }
  if (user.role === Role.PARENT) {
    const children = await prisma.child.findMany({ where: { parents: { some: { parentId: user.id } }, ...(schoolId ? { schoolId } : {}) }, select: { classId: true } });
    const ids = children.map(child => child.classId).filter((id): id is string => !!id);
    res.json({ classes: await prisma.schoolClass.findMany({ where: { id: { in: ids } }, orderBy: { name: "asc" } }) }); return;
  }
  res.status(403).json({ error: "Forbidden" });
}));

app.post("/api/admin/schools/:schoolId/classes", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const schoolId = req.params.schoolId.toString();
  if (req.principal!.schoolId && req.principal!.schoolId !== schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  const input = z.object({ id: z.string().optional(), name: z.string().trim().min(1).max(100), gradeLevel: z.string().max(40).optional(), academicYear: z.string().max(30).optional(), settings: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const { id, ...data } = input.data;
  const values = { schoolId, ...data, settings: data.settings as Prisma.InputJsonValue };
  const schoolClass = id
    ? await prisma.schoolClass.upsert({ where: { id }, create: { id, ...values }, update: values })
    : await prisma.schoolClass.upsert({ where: { schoolId_name: { schoolId, name: data.name } }, create: values, update: values });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "class.upsert", entityType: "class", entityId: schoolClass.id } });
  res.status(201).json({ class: schoolClass });
}));

// Firebase Auth remains the identity provider. Self-service sync can only create a PARENT;
// ADMIN and TEACHER accounts must be provisioned by an authorized operator.
app.post("/api/auth/sync", asyncRoute(async (req, res) => {
  if (!getApps().length) { res.status(503).json({ error: "Authentication service is not configured" }); return; }
  const token = req.header("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  if (!token) { res.status(401).json({ error: "Bearer token required" }); return; }
  let decoded;
  try { decoded = await getAuth().verifyIdToken(token); }
  catch { res.status(401).json({ error: "Invalid or expired token" }); return; }
  const firebaseUser = await getAuth().getUser(decoded.uid);
  if (!firebaseUser.email) { res.status(400).json({ error: "Verified email is required" }); return; }
  const legacyAccount = await prisma.legacyRecord.findUnique({ where: { collection_sourceId: { collection: "users_unmapped", sourceId: decoded.uid } }, select: { data: true } });
  const legacyRole = legacyAccount?.data && typeof legacyAccount.data === "object" && !Array.isArray(legacyAccount.data) ? (legacyAccount.data as Record<string, unknown>).role : undefined;
  if (typeof legacyRole === "string" && ["child", "student"].includes(legacyRole.toLowerCase())) { res.status(403).json({ error: "Child profiles do not have login accounts" }); return; }
  if (await prisma.child.findUnique({ where: { id: decoded.uid }, select: { id: true } })) { res.status(403).json({ error: "Child profiles do not have login accounts" }); return; }
  const existing = await prisma.user.findUnique({ where: { firebaseUid: decoded.uid } });
  const claimedRole = decoded.role === "ADMIN" ? Role.ADMIN : decoded.role === "TEACHER" ? Role.TEACHER : Role.PARENT;
  const claimedSchoolId = typeof decoded.schoolId === "string" ? decoded.schoolId : undefined;
  const user = await prisma.user.upsert({ where: { firebaseUid: decoded.uid }, create: { firebaseUid: decoded.uid, email: firebaseUser.email, fullName: firebaseUser.displayName || firebaseUser.email, phone: firebaseUser.phoneNumber, role: claimedRole, schoolId: claimedSchoolId }, update: { email: firebaseUser.email, fullName: firebaseUser.displayName || existing?.fullName || firebaseUser.email, phone: firebaseUser.phoneNumber ?? existing?.phone } });
  if (!existing) await prisma.auditLog.create({ data: { actorId: user.id, action: "auth.self_register", entityType: "user", entityId: user.id } });
  res.status(existing ? 200 : 201).json({ id: user.firebaseUid, databaseId: user.id, role: user.role, fullName: user.fullName, email: user.email });
}));

app.post("/api/admin/users", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const input = z.object({ firebaseUid: z.string().min(1), email: z.string().email(), fullName: z.string().trim().min(1).max(160), role: z.enum(["PARENT", "TEACHER"]), phone: z.string().max(40).optional(), schoolId: z.string().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const value = input.data;
  const schoolId = value.schoolId ?? req.principal!.schoolId ?? undefined;
  if (req.principal!.schoolId && schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  const user = await prisma.user.upsert({ where: { firebaseUid: value.firebaseUid }, create: { firebaseUid: value.firebaseUid, email: value.email, fullName: value.fullName, phone: value.phone, role: value.role, schoolId }, update: { email: value.email, fullName: value.fullName, phone: value.phone, role: value.role, schoolId } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "user.provision", entityType: "user", entityId: user.id, details: { role: user.role, schoolId: user.schoolId } } });
  res.status(201).json({ id: user.id, role: user.role });
}));

app.get("/api/me", authenticate, asyncRoute(async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.principal!.id }, include: { children: { select: { childId: true } }, taught: { select: { studentId: true } } } });
  res.json({ user: { ...publicUser(user), childrenIds: user.children.map(row => row.childId), studentIds: user.taught.map(row => row.studentId), parentIds: [] } });
}));

app.patch("/api/me", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ fullName: z.string().trim().min(1).max(160).optional(), phone: z.string().max(40).nullable().optional(), profileImageUrl: z.string().url().nullable().optional(), preferences: z.record(z.unknown()).optional(), isPremium: z.boolean().optional(), premiumExpiry: z.string().datetime().nullable().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if ((input.data.isPremium !== undefined || input.data.premiumExpiry !== undefined) && req.principal!.role !== Role.ADMIN) { res.status(403).json({ error: "Premium status requires administrator authorization" }); return; }
  const { preferences, premiumExpiry, ...fields } = input.data;
  const user = await prisma.user.update({ where: { id: req.principal!.id }, data: { ...fields, ...(preferences ? { preferences: preferences as Prisma.InputJsonValue } : {}), ...(premiumExpiry !== undefined ? { premiumExpiry: premiumExpiry ? new Date(premiumExpiry) : null } : {}) } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "user.profile_update", entityType: "user", entityId: user.id } });
  res.json({ user });
}));

app.delete("/api/me", authenticate, asyncRoute(async (req, res) => {
  const id = req.principal!.id;
  await prisma.$transaction(async transaction => {
    await transaction.auditLog.create({ data: { action: "user.account_delete", entityType: "user", entityId: id } });
    await transaction.user.delete({ where: { id } });
  });
  res.status(204).end();
}));

app.get("/api/admin/users", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const role = typeof req.query.role === "string" && ["ADMIN", "TEACHER", "PARENT"].includes(req.query.role) ? req.query.role as Role : undefined;
  const schoolId = typeof req.query.schoolId === "string" ? req.query.schoolId : req.principal!.schoolId ?? undefined;
  if (req.principal!.schoolId && schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  const users = await prisma.user.findMany({ where: { ...(role ? { role } : {}), ...(schoolId ? { schoolId } : {}), isActive: true }, include: { children: { select: { childId: true } }, taught: { select: { studentId: true } } }, orderBy: { fullName: "asc" } });
  res.json({ users: users.map(user => ({ ...publicUser(user), childrenIds: user.children.map(row => row.childId), studentIds: user.taught.map(row => row.studentId) })) });
}));

app.get("/api/users/:id", authenticate, asyncRoute(async (req, res) => {
  const id = req.params.id.toString();
  const child = await prisma.child.findUnique({ where: { id } });
  if (child) {
    if (!await canAccessChild(req.principal!, child.id)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
    res.json({ user: { id: child.id, email: "", fullName: child.fullName, role: "child", schoolId: child.schoolId, createdAt: child.createdAt.toISOString(), isActive: child.isActive, preferences: child.className ? { className: child.className } : {} } }); return;
  }
  const user = await prisma.user.findUnique({ where: { firebaseUid: id } });
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  const permitted = user.id === req.principal!.id || (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || req.principal!.schoolId === user.schoolId));
  if (!permitted) { res.status(403).json({ error: "User is outside your authorized scope" }); return; }
  res.json({ user: publicUser(user) });
}));

app.get("/api/admin/parents/:firebaseUid/devices", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const parent = await prisma.user.findUnique({ where: { firebaseUid: req.params.firebaseUid.toString() } });
  if (!parent || parent.role !== Role.PARENT || (req.principal!.schoolId && req.principal!.schoolId !== parent.schoolId)) { res.status(404).json({ error: "Parent not found" }); return; }
  const relations = await prisma.parentChild.findMany({ where: { parentId: parent.id }, select: { childId: true } });
  const devices = await prisma.device.findMany({ where: { OR: [{ ownerId: parent.id }, { childId: { in: relations.map(row => row.childId) } }] }, orderBy: { updatedAt: "desc" } });
  res.json({ devices: devices.map(({ fcmToken: _token, deviceKey: _key, deviceSecretHash: _secret, ...device }) => ({ ...device, userId: device.childId ?? device.ownerId, deviceName: device.name, type: device.platform.toLowerCase(), deviceModel: device.model, isActive: device.isAuthorized })) });
}));

app.post("/api/admin/children/:childId/teachers", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const input = z.object({ teacherFirebaseUid: z.string().min(1) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const childId = req.params.childId.toString();
  const [child, teacher] = await Promise.all([
    prisma.child.findUnique({ where: { id: childId } }),
    prisma.user.findUnique({ where: { firebaseUid: input.data.teacherFirebaseUid } }),
  ]);
  if (!child || !teacher || teacher.role !== Role.TEACHER || !teacher.isActive) { res.status(404).json({ error: "Child or teacher not found" }); return; }
  if (req.principal!.schoolId && (child.schoolId !== req.principal!.schoolId || teacher.schoolId !== req.principal!.schoolId)) { res.status(403).json({ error: "Child or teacher is outside your school" }); return; }
  await prisma.teacherStudent.upsert({ where: { teacherId_studentId: { teacherId: teacher.id, studentId: child.id } }, create: { teacherId: teacher.id, studentId: child.id }, update: {} });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.teacher_link", entityType: "child", entityId: child.id, details: { teacherId: teacher.id } } });
  res.json({ success: true });
}));

app.get("/api/notifications", authenticate, asyncRoute(async (req, res) => {
  const take = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
  const before = typeof req.query.before === "string" ? new Date(req.query.before) : undefined;
  if (before && Number.isNaN(before.valueOf())) { res.status(400).json({ error: "Invalid before cursor" }); return; }
  const rows = await prisma.notification.findMany({ where: { recipientId: req.principal!.id, ...(before ? { createdAt: { lt: before } } : {}) }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take });
  res.json({ notifications: rows.map(toApiNotification), nextCursor: rows.length === take ? rows[rows.length - 1].createdAt.toISOString() : null });
}));

app.get("/api/children", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  const where: Prisma.ChildWhereInput = user.role === Role.ADMIN
    ? { ...(user.schoolId ? { schoolId: user.schoolId } : {}) }
    : user.role === Role.PARENT
      ? { parents: { some: { parentId: user.id } } }
      : { teachers: { some: { teacherId: user.id } } };
  const children = await prisma.child.findMany({ where, orderBy: { fullName: "asc" } });
  res.json({ children });
}));

app.post("/api/children", authenticate, allow(Role.ADMIN, Role.TEACHER, Role.PARENT), asyncRoute(async (req, res) => {
  const input = z.object({ id: z.string().min(1).max(200), fullName: z.string().trim().min(1).max(160), schoolId: z.string().optional(), className: z.string().max(80).optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const user = req.principal!;
  let schoolId: string | undefined;
  if (user.role === Role.TEACHER) {
    if (!user.schoolId) { res.status(403).json({ error: "Teacher has no assigned school" }); return; }
    schoolId = user.schoolId;
  } else if (user.role === Role.ADMIN) {
    schoolId = input.data.schoolId ?? user.schoolId ?? undefined;
    if (user.schoolId && schoolId !== user.schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  } else {
    schoolId = user.schoolId ?? input.data.schoolId;
    if (schoolId && !await prisma.school.findFirst({ where: { id: schoolId, isActive: true }, select: { id: true } })) { res.status(400).json({ error: "Active school not found" }); return; }
  }
  const existingChild = await prisma.child.findUnique({ where: { id: input.data.id }, select: { id: true } });
  if (existingChild && !await canAccessChild(user, existingChild.id)) { res.status(403).json({ error: "This child is already registered outside your authorized scope" }); return; }
  const schoolClass = schoolId && input.data.className
    ? await prisma.schoolClass.findFirst({ where: { schoolId, name: input.data.className }, select: { id: true } })
    : null;
  const child = await prisma.child.upsert({ where: { id: input.data.id }, create: { id: input.data.id, fullName: input.data.fullName, schoolId, className: input.data.className, classId: schoolClass?.id }, update: { fullName: input.data.fullName, schoolId, className: input.data.className, classId: schoolClass?.id } });
  if (user.role === Role.PARENT) await prisma.parentChild.upsert({ where: { parentId_childId: { parentId: user.id, childId: child.id } }, create: { parentId: user.id, childId: child.id }, update: {} });
  if (user.role === Role.TEACHER) await prisma.teacherStudent.upsert({ where: { teacherId_studentId: { teacherId: user.id, studentId: child.id } }, create: { teacherId: user.id, studentId: child.id }, update: {} });
  await prisma.auditLog.create({ data: { actorId: user.id, action: "child.register", entityType: "child", entityId: child.id } });
  res.status(201).json({ child });
}));

app.delete("/api/children/:childId/link", authenticate, allow(Role.PARENT, Role.TEACHER), asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  if (req.principal!.role === Role.PARENT) await prisma.parentChild.delete({ where: { parentId_childId: { parentId: req.principal!.id, childId } } });
  else await prisma.teacherStudent.delete({ where: { teacherId_studentId: { teacherId: req.principal!.id, studentId: childId } } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.unlink", entityType: "child", entityId: childId } });
  res.status(204).end();
}));

app.post("/api/device-links", authenticate, allow(Role.ADMIN, Role.TEACHER, Role.PARENT), asyncRoute(async (req, res) => {
  const input = z.object({ childId: z.string().min(1), validForMinutes: z.number().int().min(1).max(60).default(30) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const user = req.principal!;
  if (!await canAccessChild(user, input.data.childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  if (user.role === Role.PARENT) {
    const count = await prisma.device.count({ where: { child: { parents: { some: { parentId: user.id } } }, isAuthorized: true } });
    if (count >= 3) { res.status(409).json({ error: "Parent device limit reached" }); return; }
  }
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + input.data.validForMinutes * 60_000);
  await prisma.deviceLinkToken.create({ data: { tokenHash: createHash("sha256").update(token).digest("hex"), childId: input.data.childId, actorId: user.id, expiresAt } });
  res.status(201).json({ token, expiresAt: expiresAt.toISOString() });
}));

// A one-use, short-lived QR token authorizes a child device to pair without a child account.
app.post("/api/device-links/register", asyncRoute(async (req, res) => {
  const input = z.object({ token: z.string().min(20).max(200), deviceKey: z.string().min(1).max(200), deviceSecret: z.string().min(24).max(200), platform: z.enum(["ANDROID", "IOS", "WINDOWS", "MACOS", "WEB"]), name: z.string().min(1).max(120), model: z.string().max(120).optional(), osVersion: z.string().max(120).optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const value = input.data;
  const tokenHash = createHash("sha256").update(value.token).digest("hex");
  const device = await prisma.$transaction(async transaction => {
    const now = new Date();
    const link = await transaction.deviceLinkToken.findUnique({ where: { tokenHash } });
    if (!link || link.usedAt || link.expiresAt <= now) return null;
    const claimed = await transaction.deviceLinkToken.updateMany({ where: { tokenHash, usedAt: null, expiresAt: { gt: now } }, data: { usedAt: now } });
    if (!claimed.count) return null;
    const child = await transaction.child.findUnique({ where: { id: link.childId }, select: { schoolId: true } });
    if (!child) return null;
    const result = await transaction.device.create({ data: { deviceKey: value.deviceKey, childId: link.childId, schoolId: child.schoolId, ownerId: link.actorId, platform: value.platform, name: value.name, model: value.model, osVersion: value.osVersion, deviceSecretHash: createHash("sha256").update(value.deviceSecret).digest("hex"), status: "ONLINE", isAuthorized: true, lastSeen: new Date() } });
    await transaction.deviceRegistration.create({ data: { deviceId: result.id, actorId: link.actorId, authorized: true } });
    await transaction.deviceLinkToken.update({ where: { tokenHash }, data: { deviceId: result.id } });
    const owner = await transaction.user.findUnique({ where: { id: link.actorId }, select: { firebaseUid: true } });
    return { device: result, childId: link.childId, ownerFirebaseUid: owner?.firebaseUid };
  });
  if (!device) { res.status(410).json({ error: "Pairing token is invalid, expired, or already used" }); return; }
  res.status(201).json({ id: device.device.id, childId: device.childId, parentFirebaseUid: device.ownerFirebaseUid, status: device.device.status });
}));

app.post("/api/device-events", asyncRoute(async (req, res) => {
  const input = z.object({ deviceId: z.string().min(1), childId: z.string().min(1), deviceSecret: z.string().min(24).max(200), type: z.enum(["blocked_content", "app_usage_summary", "tamper_event", "device_heartbeat"]), payload: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const event = input.data;
  const device = await prisma.device.findUnique({ where: { id: event.deviceId } });
  if (!device || !device.isAuthorized || device.childId !== event.childId || !device.ownerId || !device.deviceSecretHash) { res.status(403).json({ error: "Device registration is invalid" }); return; }
  const actualHash = Buffer.from(createHash("sha256").update(event.deviceSecret).digest("hex"), "hex");
  const expectedHash = Buffer.from(device.deviceSecretHash, "hex");
  if (actualHash.length !== expectedHash.length || !timingSafeEqual(actualHash, expectedHash)) { res.status(403).json({ error: "Device credentials are invalid" }); return; }
  const createdAt = new Date();
  await prisma.$transaction([
    prisma.deviceActivityEvent.create({ data: { deviceId: device.id, childId: device.childId, type: event.type, payload: event.payload as Prisma.InputJsonValue, createdAt } }),
    prisma.device.update({ where: { id: device.id }, data: { status: event.type === "tamper_event" ? "UNKNOWN" : "ONLINE", lastSeen: createdAt, model: z.string().max(120).optional().parse(event.payload.deviceModel) ?? device.model, osVersion: z.string().max(120).optional().parse(event.payload.osVersion) ?? device.osVersion } }),
  ]);
  if (event.type === "blocked_content" || event.type === "tamper_event") {
    const parent = await prisma.user.findUnique({ where: { id: device.ownerId }, select: { isActive: true } });
    if (parent?.isActive) {
      const blockedTerm = typeof event.payload.blockedTerm === "string" ? event.payload.blockedTerm.slice(0, 160) : "unsafe content";
      const title = event.type === "blocked_content" ? "Unsafe content blocked" : "Child device protection alert";
      const body = event.type === "blocked_content" ? `${device.name} blocked: ${blockedTerm}` : `${device.name}: ${typeof event.payload.message === "string" ? event.payload.message.slice(0, 300) : "Protection status changed."}`;
      const notification = await prisma.notification.create({ data: { recipientId: device.ownerId, childId: device.childId, title, body, type: event.type === "tamper_event" ? "behavior" : "system", relatedEntity: "device_activity", relatedId: device.id, payload: { source: event.type, deviceId: device.id, childId: device.childId, blockedTerm } } });
      await deliver(notification.id, device.ownerId, title, body, { source: event.type, deviceId: device.id, childId: device.childId, blockedTerm });
    }
  }
  res.status(202).json({ accepted: true });
}));

app.get("/api/notifications/unread-count", authenticate, asyncRoute(async (req, res) => {
  const count = await prisma.notification.count({ where: { recipientId: req.principal!.id, isRead: false } });
  res.json({ count });
}));

app.get("/api/notifications/preferences", authenticate, asyncRoute(async (req, res) => {
  const preference = await prisma.notificationPreference.findUnique({ where: { userId: req.principal!.id } });
  res.json({ preferences: preference ?? { userId: req.principal!.id, pushEnabled: true, types: {} } });
}));

app.patch("/api/notifications/preferences", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ pushEnabled: z.boolean().optional(), types: z.record(z.boolean()).optional() }).refine(value => value.pushEnabled !== undefined || value.types !== undefined).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const preference = await prisma.notificationPreference.upsert({ where: { userId: req.principal!.id }, create: { userId: req.principal!.id, pushEnabled: input.data.pushEnabled, types: input.data.types }, update: input.data });
  res.json({ preferences: preference });
}));

app.patch("/api/notifications/:id/read", authenticate, asyncRoute(async (req, res) => {
  const notificationId = req.params.id.toString();
  const result = await prisma.notification.updateMany({ where: { id: notificationId, recipientId: req.principal!.id, isRead: false }, data: { isRead: true, readAt: new Date() } });
  if (!result.count && !await prisma.notification.findFirst({ where: { id: notificationId, recipientId: req.principal!.id } })) { res.status(404).json({ error: "Notification not found" }); return; }
  res.json({ success: true });
}));

app.patch("/api/notifications/read-all", authenticate, asyncRoute(async (req, res) => {
  const result = await prisma.notification.updateMany({ where: { recipientId: req.principal!.id, isRead: false }, data: { isRead: true, readAt: new Date() } });
  res.json({ updated: result.count });
}));

// Records are committed before FCM delivery. A delivery error only updates status and
// never removes the history row.
app.post("/api/notifications", authenticate, allow(Role.ADMIN, Role.TEACHER, Role.PARENT), asyncRoute(async (req, res) => {
  const input = z.object({ title: z.string().trim().min(1).max(160), body: z.string().trim().min(1).max(4000), recipientFirebaseUid: z.string().min(1), type: z.string().default("system"), childId: z.string().optional(), relatedEntity: z.string().optional(), relatedId: z.string().optional(), payload: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const data = input.data;
  const recipient = await prisma.user.findUnique({ where: { firebaseUid: data.recipientFirebaseUid } });
  if (!recipient || !recipient.isActive) { res.status(404).json({ error: "Recipient not found" }); return; }
  if (req.principal!.role === Role.TEACHER && !data.childId) { res.status(403).json({ error: "Teachers must notify recipients through an authorized child" }); return; }
  if (req.principal!.role === Role.PARENT) {
    if (recipient.id !== req.principal!.id || !data.childId || !await canAccessChild(req.principal!, data.childId)) { res.status(403).json({ error: "Parents can create notifications only for themselves and their linked children" }); return; }
  } else if (data.childId && !await canAccessChild(req.principal!, data.childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  if (req.principal!.role === Role.TEACHER) {
    const isParentOfChild = recipient.role === Role.PARENT && !!await prisma.parentChild.findUnique({ where: { parentId_childId: { parentId: recipient.id, childId: data.childId! } } });
    const isTeacherOfChild = recipient.role === Role.TEACHER && !!await prisma.teacherStudent.findUnique({ where: { teacherId_studentId: { teacherId: recipient.id, studentId: data.childId! } } });
    const isSameSchoolAdmin = recipient.role === Role.ADMIN && recipient.schoolId === req.principal!.schoolId;
    if (!(isParentOfChild || isTeacherOfChild || isSameSchoolAdmin)) { res.status(403).json({ error: "Recipient is outside your authorized child scope" }); return; }
  }
  if (req.principal!.role === Role.ADMIN && req.principal!.schoolId) {
    if (data.childId) {
      const child = await prisma.child.findUnique({ where: { id: data.childId }, select: { schoolId: true } });
      if (child?.schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "Child is outside your school" }); return; }
      if (recipient.role === Role.PARENT && !await prisma.parentChild.findUnique({ where: { parentId_childId: { parentId: recipient.id, childId: data.childId } } })) { res.status(403).json({ error: "Recipient is not linked to this child" }); return; }
    } else if (recipient.schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "Recipient is outside your school" }); return; }
  }
  const notification = await prisma.notification.create({ data: { recipientId: recipient.id, childId: data.childId, title: data.title, body: data.body, type: data.type, relatedEntity: data.relatedEntity, relatedId: data.relatedId, payload: data.payload as Prisma.InputJsonValue } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "notification.create", entityType: "notification", entityId: notification.id } });
  await deliver(notification.id, recipient.id, data.title, data.body, data.payload);
  res.status(201).json(toApiNotification(await prisma.notification.findUniqueOrThrow({ where: { id: notification.id } })));
}));

app.post("/api/notifications/child-parents", authenticate, allow(Role.ADMIN, Role.TEACHER), asyncRoute(async (req, res) => {
  const input = z.object({ childId: z.string().min(1), title: z.string().trim().min(1).max(160), body: z.string().trim().min(1).max(4000), type: z.string().default("system"), payload: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const { childId, title, body, type, payload } = input.data;
  if (!await canAccessChild(req.principal!, childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  const links = await prisma.parentChild.findMany({ where: { childId, parent: { isActive: true } }, select: { parentId: true } });
  const rows = await prisma.notification.createManyAndReturn({ data: links.map(({ parentId }) => ({ recipientId: parentId, childId, title, body, type, payload: payload as Prisma.InputJsonValue })) });
  await Promise.all(rows.map(row => deliver(row.id, row.recipientId, title, body, payload)));
  res.status(201).json({ created: rows.length });
}));

app.post("/api/notifications/broadcast", authenticate, allow(Role.ADMIN, Role.TEACHER), asyncRoute(async (req, res) => {
  const input = z.object({ title: z.string().trim().min(1).max(160), body: z.string().trim().min(1).max(4000), roles: z.array(z.string()).min(1), schoolId: z.string().optional(), childId: z.string().optional(), type: z.string().default("system"), payload: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const { title, body, type, payload, childId } = input.data;
  const roles = new Set(input.data.roles.map(role => role.toUpperCase().replace(/S$/, "")));
  if (req.principal!.role === Role.TEACHER && !childId) { res.status(403).json({ error: "Teachers must target an authorized child" }); return; }
  if (childId && !await canAccessChild(req.principal!, childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  const schoolId = req.principal!.role === Role.TEACHER ? req.principal!.schoolId : (input.data.schoolId ?? req.principal!.schoolId);
  if (req.principal!.role === Role.ADMIN && req.principal!.schoolId && schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  const recipientWhere: Prisma.UserWhereInput[] = [];
  if (roles.has("PARENT")) recipientWhere.push({ role: Role.PARENT, children: { some: { ...(childId ? { childId } : {}), ...(schoolId ? { child: { schoolId } } : {}), ...(req.principal!.role === Role.TEACHER ? { child: { teachers: { some: { teacherId: req.principal!.id } } } } : {}) } } });
  if (req.principal!.role === Role.ADMIN && roles.has("TEACHER")) recipientWhere.push({ role: Role.TEACHER, ...(schoolId ? { schoolId } : {}) });
  if (req.principal!.role === Role.ADMIN && roles.has("ADMIN")) recipientWhere.push({ role: Role.ADMIN, ...(schoolId ? { schoolId } : {}) });
  const recipients = recipientWhere.length ? await prisma.user.findMany({ where: { isActive: true, OR: recipientWhere }, select: { id: true } }) : [];
  if (!recipients.length) { res.json({ created: 0 }); return; }
  const rows = await prisma.notification.createManyAndReturn({ data: recipients.map(({ id }) => ({ recipientId: id, childId, title, body, type, payload: payload as Prisma.InputJsonValue })) });
  await Promise.all(rows.map(row => deliver(row.id, row.recipientId, title, body, payload)));
  res.status(201).json({ created: rows.length });
}));

app.delete("/api/notifications/:id", authenticate, asyncRoute(async (req, res) => {
  const result = await prisma.notification.deleteMany({ where: { id: req.params.id.toString(), recipientId: req.principal!.id } });
  if (!result.count) { res.status(404).json({ error: "Notification not found" }); return; }
  res.status(204).end();
}));

app.post("/api/notifications/delete-related", authenticate, asyncRoute(async (req, res) => {
  const filters = z.record(z.string()).safeParse(req.body);
  if (!filters.success || !Object.keys(filters.data).length || Object.keys(filters.data).some(key => !["announcementId", "resultId", "feedbackId", "activityId"].includes(key))) { res.status(400).json({ error: "Invalid notification reference filter" }); return; }
  const rows = await prisma.notification.findMany({ where: { recipientId: req.principal!.id }, select: { id: true, payload: true } });
  const ids = rows.filter(row => Object.entries(filters.data).some(([key, value]) => (row.payload as Record<string, unknown>)[key] === value)).map(row => row.id);
  const result = await prisma.notification.deleteMany({ where: { recipientId: req.principal!.id, id: { in: ids } } });
  res.json({ deleted: result.count });
}));

app.post("/api/devices/push-token", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ token: z.string().min(16), platform: z.enum(["ANDROID", "IOS", "WINDOWS", "MACOS", "WEB"]), name: z.string().max(120).default("KidGuard device"), model: z.string().max(120).optional(), osVersion: z.string().max(120).optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const value = input.data;
  const existing = await prisma.device.findUnique({ where: { fcmToken: value.token }, select: { id: true } });
  const fields = { ownerId: req.principal!.id, platform: value.platform, name: value.name, model: value.model, osVersion: value.osVersion, fcmToken: value.token, status: "ONLINE" as const, lastSeen: new Date() };
  const device = existing
    ? await prisma.device.update({ where: { id: existing.id }, data: fields })
    : await prisma.device.create({ data: { deviceKey: `fcm:${value.token}`, ...fields } });
  res.json({ id: device.id });
}));

app.post("/api/devices/register", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ deviceKey: z.string().min(1).max(200), childId: z.string().min(1), platform: z.enum(["ANDROID", "IOS", "WINDOWS", "MACOS", "WEB"]), name: z.string().min(1).max(120), model: z.string().max(120).optional(), osVersion: z.string().max(120).optional(), appVersion: z.string().max(80).optional(), fcmToken: z.string().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const value = input.data;
  if (!await canAccessChild(req.principal!, value.childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  const child = await prisma.child.findUniqueOrThrow({ where: { id: value.childId } });
  const existing = await prisma.device.findUnique({ where: { deviceKey: value.deviceKey } });
  if (existing && existing.childId !== value.childId && existing.ownerId !== req.principal!.id) { res.status(409).json({ error: "Device key is already registered" }); return; }
  const deviceFields = { childId: value.childId, platform: value.platform, name: value.name, model: value.model, osVersion: value.osVersion, appVersion: value.appVersion, fcmToken: value.fcmToken, ownerId: existing?.ownerId ?? req.principal!.id, schoolId: child.schoolId, isAuthorized: true, status: "ONLINE" as const, lastSeen: new Date() };
  const device = existing
    ? await prisma.device.update({ where: { id: existing.id }, data: deviceFields })
    : await prisma.device.create({ data: { deviceKey: value.deviceKey, ...deviceFields } });
  await prisma.deviceRegistration.upsert({ where: { deviceId_actorId: { deviceId: device.id, actorId: req.principal!.id } }, create: { deviceId: device.id, actorId: req.principal!.id, authorized: true }, update: { authorized: true } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "device.register", entityType: "device", entityId: device.id } });
  res.status(201).json({ id: device.id, status: device.status });
}));

app.patch("/api/devices/:deviceId/status", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ status: z.enum(["ONLINE", "OFFLINE", "UNKNOWN"]), batteryLevel: z.number().min(0).max(100).optional(), isCharging: z.boolean().optional(), storageUsed: z.number().nonnegative().optional(), storageTotal: z.number().nonnegative().optional(), memoryUsed: z.number().nonnegative().optional(), memoryTotal: z.number().nonnegative().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const device = await prisma.device.findUnique({ where: { id: req.params.deviceId.toString() } });
  if (!device) { res.status(404).json({ error: "Device not found" }); return; }
  const permitted = device.childId ? await canAccessChild(req.principal!, device.childId) : device.ownerId === req.principal!.id || (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || device.schoolId === req.principal!.schoolId));
  if (!permitted) { res.status(403).json({ error: "Device is outside your authorized scope" }); return; }
  const updated = await prisma.device.update({ where: { id: device.id }, data: { ...input.data, lastSeen: new Date() } });
  res.json({ device: { id: updated.id, status: updated.status, lastSeen: updated.lastSeen } });
}));

app.get("/api/devices", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  const where: Prisma.DeviceWhereInput = user.role === Role.ADMIN
    ? { ...(user.schoolId ? { schoolId: user.schoolId } : {}) }
    : user.role === Role.PARENT
      ? { OR: [{ ownerId: user.id }, { child: { parents: { some: { parentId: user.id } } } }] }
      : { OR: [{ ownerId: user.id }, { child: { teachers: { some: { teacherId: user.id } } } }] };
  const devices = await prisma.device.findMany({ where, orderBy: { updatedAt: "desc" } });
  res.json({ devices: devices.map(({ fcmToken: _token, deviceKey: _deviceKey, deviceSecretHash: _secret, ...device }) => ({ ...device, userId: device.childId ?? device.ownerId, deviceName: device.name, type: device.platform.toLowerCase(), deviceModel: device.model, isActive: device.isAuthorized })) });
}));

app.get("/api/devices/:deviceId", authenticate, asyncRoute(async (req, res) => {
  const device = await prisma.device.findUnique({ where: { id: req.params.deviceId.toString() } });
  if (!device) { res.status(404).json({ error: "Device not found" }); return; }
  const permitted = device.childId ? await canAccessChild(req.principal!, device.childId) : device.ownerId === req.principal!.id || (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || device.schoolId === req.principal!.schoolId));
  if (!permitted) { res.status(403).json({ error: "Device is outside your authorized scope" }); return; }
  const { fcmToken: _token, deviceKey: _key, deviceSecretHash: _secret, ...safe } = device;
  res.json({ device: { ...safe, userId: safe.childId ?? safe.ownerId, deviceName: safe.name, type: safe.platform.toLowerCase(), deviceModel: safe.model, isActive: safe.isAuthorized } });
}));

app.get("/api/children/:childId/activity", authenticate, asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  const take = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
  const events = await prisma.deviceActivityEvent.findMany({ where: { childId }, orderBy: { createdAt: "desc" }, take });
  res.json({ events: events.map(event => ({ id: event.id, type: event.type, childId: event.childId, deviceId: event.deviceId, deviceName: typeof (event.payload as Record<string, unknown>).deviceName === "string" ? (event.payload as Record<string, unknown>).deviceName : "Device", createdAt: event.createdAt.toISOString(), ...(event.payload as Record<string, unknown>) })) });
}));

app.post("/api/children/:childId/locations", authenticate, asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  const input = z.object({ deviceId: z.string().min(1), latitude: z.number().min(-90).max(90), longitude: z.number().min(-180).max(180), altitude: z.number().optional(), accuracy: z.number().nonnegative().optional(), speed: z.number().optional(), bearing: z.number().optional(), address: z.string().max(500).optional(), placeName: z.string().max(200).optional(), timestamp: z.string().datetime().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  const device = await prisma.device.findFirst({ where: { id: input.data.deviceId, childId, isAuthorized: true } });
  if (!device) { res.status(403).json({ error: "Authorized child device required" }); return; }
  const location = await prisma.deviceLocation.create({ data: { ...input.data, childId, timestamp: input.data.timestamp ? new Date(input.data.timestamp) : new Date() } });
  await prisma.device.update({ where: { id: device.id }, data: { lastSeen: new Date(), status: "ONLINE" } });
  res.status(201).json({ location });
}));

app.get("/api/children/:childId/locations", authenticate, asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  const from = typeof req.query.from === "string" ? new Date(req.query.from) : new Date(Date.now() - 7 * 86_400_000);
  const to = typeof req.query.to === "string" ? new Date(req.query.to) : new Date();
  if (Number.isNaN(from.valueOf()) || Number.isNaN(to.valueOf())) { res.status(400).json({ error: "Invalid location time range" }); return; }
  const take = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
  const locations = await prisma.deviceLocation.findMany({ where: { childId, timestamp: { gte: from, lte: to } }, orderBy: { timestamp: "desc" }, take });
  res.json({ locations });
}));

app.post("/api/children/:childId/screen-time", authenticate, asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  const input = z.object({ deviceId: z.string().optional(), date: z.string().datetime(), totalMinutes: z.number().int().nonnegative(), unlockedCount: z.number().int().nonnegative().default(0), appUsage: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  const device = input.data.deviceId
    ? await prisma.device.findFirst({ where: { id: input.data.deviceId, childId, isAuthorized: true } })
    : await prisma.device.findFirst({ where: { childId, isAuthorized: true }, orderBy: { lastSeen: "desc" } });
  if (!device) { res.status(403).json({ error: "Authorized child device required" }); return; }
  const date = nairobiDayStart(new Date(input.data.date));
  const record = await prisma.$transaction(async transaction => {
    const existing = await transaction.screenTimeRecord.findUnique({ where: { deviceId_date: { deviceId: device.id, date } } });
    const currentApps = existing?.appUsage && typeof existing.appUsage === "object" && !Array.isArray(existing.appUsage) ? existing.appUsage as Record<string, unknown> : {};
    const mergedApps = { ...currentApps };
    for (const [key, raw] of Object.entries(input.data.appUsage)) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) { mergedApps[key] = raw; continue; }
      const incoming = raw as Record<string, unknown>;
      const previous = currentApps[key] && typeof currentApps[key] === "object" && !Array.isArray(currentApps[key]) ? currentApps[key] as Record<string, unknown> : {};
      mergedApps[key] = { ...previous, ...incoming, minutesUsed: Number(previous.minutesUsed ?? 0) + Number(incoming.minutesUsed ?? 0), launches: Number(previous.launches ?? 0) + Number(incoming.launches ?? 0) };
    }
    if (!existing) return transaction.screenTimeRecord.create({ data: { deviceId: device.id, childId, date, totalMinutes: input.data.totalMinutes, unlockedCount: input.data.unlockedCount, appUsage: mergedApps as Prisma.InputJsonValue } });
    return transaction.screenTimeRecord.update({ where: { id: existing.id }, data: { totalMinutes: { increment: input.data.totalMinutes }, unlockedCount: { increment: input.data.unlockedCount }, appUsage: mergedApps as Prisma.InputJsonValue } });
  });
  res.status(201).json({ record });
}));

app.get("/api/children/:childId/screen-time", authenticate, asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  const from = typeof req.query.from === "string" ? new Date(req.query.from) : new Date(Date.now() - 7 * 86_400_000);
  const to = typeof req.query.to === "string" ? new Date(req.query.to) : new Date();
  if (Number.isNaN(from.valueOf()) || Number.isNaN(to.valueOf())) { res.status(400).json({ error: "Invalid screen-time range" }); return; }
  const records = await prisma.screenTimeRecord.findMany({ where: { childId, date: { gte: from, lte: to } }, orderBy: { date: "desc" } });
  res.json({ records });
}));

async function deliver(id: string, recipientId: string, title: string, body: string, payload: Record<string, unknown>) {
  const preference = await prisma.notificationPreference.findUnique({ where: { userId: recipientId } });
  if (preference?.pushEnabled === false) {
    await prisma.notification.update({ where: { id }, data: { deliveryStatus: "SKIPPED" } });
    return;
  }
  const tokens = (await prisma.device.findMany({ where: { ownerId: recipientId, fcmToken: { not: null } }, select: { fcmToken: true } })).map(d => d.fcmToken!).filter(Boolean);
  if (!tokens.length || !getApps().length) return;
  try {
    const { getMessaging } = await import("firebase-admin/messaging");
    const response = await getMessaging().sendEachForMulticast({ tokens, notification: { title, body }, data: { notificationId: id, ...Object.fromEntries(Object.entries(payload).map(([key, value]) => [key, typeof value === "string" ? value : JSON.stringify(value)])) } });
    await prisma.notification.update({ where: { id }, data: { deliveryStatus: response.successCount ? "SENT" : "FAILED", deliveryError: response.failureCount ? `${response.failureCount} device(s) failed` : null, deliveredAt: response.successCount ? new Date() : null } });
  } catch (error) {
    await prisma.notification.update({ where: { id }, data: { deliveryStatus: "FAILED", deliveryError: error instanceof Error ? error.message.slice(0, 500) : "FCM delivery failed" } });
  }
}

function toApiNotification(row: { id: string; recipientId: string; title: string; body: string; type: string; relatedEntity: string | null; relatedId: string | null; payload: Prisma.JsonValue; isRead: boolean; createdAt: Date; readAt: Date | null; deliveryStatus: string; childId: string | null }) {
  return { id: row.id, recipientId: row.recipientId, title: row.title, body: row.body, type: row.type, relatedEntity: row.relatedEntity, relatedId: row.relatedId, payload: row.payload, isRead: row.isRead, createdAt: row.createdAt.toISOString(), readAt: row.readAt?.toISOString() ?? null, deliveryStatus: row.deliveryStatus, childId: row.childId };
}

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error("API request failed", err);
  res.status(500).json({ error: "Internal server error" });
});

function previousNairobiDay() {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: "Africa/Nairobi", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date());
  const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
  const todayKey = `${values.year}-${values.month}-${values.day}`;
  const todayUtc = Date.parse(`${todayKey}T00:00:00.000Z`);
  return { dayKey: new Date(todayUtc - 86_400_000).toISOString().slice(0, 10), start: new Date(todayUtc - 27 * 3_600_000), end: new Date(todayUtc - 3 * 3_600_000) };
}

function nairobiDayStart(date: Date) {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: "Africa/Nairobi", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(date);
  const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return new Date(Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day)) - 3 * 3_600_000);
}

async function createDailyUsageSummaries() {
  const { dayKey, start, end } = previousNairobiDay();
  const devices = await prisma.device.findMany({ where: { ownerId: { not: null }, isAuthorized: true }, select: { id: true, ownerId: true, childId: true, name: true, status: true } });
  const byParent = new Map<string, typeof devices>();
  for (const device of devices) {
    if (!device.ownerId) continue;
    const current = byParent.get(device.ownerId) ?? [];
    current.push(device);
    byParent.set(device.ownerId, current);
  }
  for (const [parentId, parentDevices] of byParent) {
    if (await prisma.dailyUsageSummary.findUnique({ where: { parentId_dayKey: { parentId, dayKey } }, select: { id: true } })) continue;
    const deviceIds = parentDevices.map(device => device.id);
    const events = await prisma.deviceActivityEvent.findMany({ where: { deviceId: { in: deviceIds }, type: "app_usage_summary", createdAt: { gte: start, lt: end } }, select: { payload: true } });
    const apps = new Map<string, { appName: string; minutes: number }>();
    let totalMinutes = 0;
    for (const event of events) {
      const payload = event.payload as Record<string, unknown>;
      const appRows = Array.isArray(payload.apps) ? payload.apps : [];
      for (const row of appRows) {
        if (!row || typeof row !== "object") continue;
        const item = row as Record<string, unknown>;
        const appName = typeof item.appName === "string" ? item.appName : typeof item.packageName === "string" ? item.packageName : "App";
        const minutes = Number(item.minutesUsed ?? item.minutes ?? 0);
        if (!Number.isFinite(minutes) || minutes <= 0) continue;
        totalMinutes += minutes;
        const current = apps.get(appName) ?? { appName, minutes: 0 };
        current.minutes += minutes;
        apps.set(appName, current);
      }
    }
    const topApps = [...apps.values()].sort((a, b) => b.minutes - a.minutes).slice(0, 5).map(app => ({ ...app, minutes: Math.round(app.minutes) }));
    const total = Math.round(totalMinutes);
    const hours = Math.floor(total / 60);
    const minutes = total % 60;
    const duration = hours ? `${hours}h ${minutes}m` : `${minutes}m`;
    const appsText = topApps.slice(0, 3).map(item => `${item.appName} ${item.minutes}m`).join(", ");
    const active = parentDevices.filter(device => device.status === "ONLINE").length;
    const inactive = parentDevices.length - active;
    const body = topApps.length
      ? `Matumizi ya leo: ${duration}. Apps kuu: ${appsText}. Active: ${active}, inactive: ${inactive}.`
      : `Leo hakuna matumizi makubwa yaliyorekodiwa. Active: ${active}, inactive: ${inactive}.`;
    const title = "Muhtasari wa matumizi ya leo";
    try {
      const notification = await prisma.$transaction(async transaction => {
        if (await transaction.dailyUsageSummary.findUnique({ where: { parentId_dayKey: { parentId, dayKey } }, select: { id: true } })) return null;
        await transaction.dailyUsageSummary.create({ data: { parentId, dayKey, totalMinutes: total, topApps: topApps as Prisma.InputJsonValue, childIds: [...new Set(parentDevices.flatMap(device => device.childId ? [device.childId] : []))], deviceIds, eventCount: events.length, activeDevices: active, inactiveDevices: inactive } });
        return transaction.notification.create({ data: { recipientId: parentId, title, body, type: "system", relatedEntity: "daily_usage_summary", relatedId: dayKey, payload: { source: "daily_usage_summary", dayKey, totalMinutes: total, activeDevices: active, inactiveDevices: inactive } } });
      });
      if (notification) await deliver(notification.id, parentId, notification.title, notification.body, notification.payload as Record<string, unknown>);
    } catch (error) {
      if (!(error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002")) throw error;
    }
  }
}

const port = Number(process.env.PORT) || 8080;
const server = app.listen(port, () => console.log(`KidGuard API listening on ${port}`));
const dailySummaryTimer = setInterval(() => { void createDailyUsageSummaries().catch(error => console.error("Daily usage summary job failed", error)); }, 15 * 60 * 1000);
void createDailyUsageSummaries().catch(error => console.error("Daily usage summary job failed", error));
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => server.close(() => { clearInterval(dailySummaryTimer); void prisma.$disconnect().finally(() => process.exit(0)); }));
