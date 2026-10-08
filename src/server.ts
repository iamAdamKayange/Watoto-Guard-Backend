import "dotenv/config";
import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { Prisma, PrismaClient, Role, SchoolRequestStatus } from "@prisma/client";
import { OAuth2Client } from "google-auth-library";
import { z } from "zod";
import { createHash, createHmac, randomBytes, randomInt, scryptSync, timingSafeEqual } from "node:crypto";
import { sendSendlibEmail, sendSendlibOtpEmail } from "./sendlib";
import { AI_MAX_REQUESTS_PER_MINUTE, boundAiContext, buildConversationWindow, canUseAiGuardian, classifyAiQuestionIntent, classifyNotificationVoice, classifySafetyVoice, cleanContextText, AiAssistantRequestError, ownedConversationWhere, requestAiAssistant, resolveAiAssistantConfiguration, validateChatMessages } from "./ai_guardian";

const prisma = new PrismaClient();
const app = express();
app.disable("x-powered-by");
app.use(helmet());
const configuredCorsOrigins = (process.env.CORS_ORIGINS ?? "").split(",").map(origin => origin.trim()).filter(Boolean);
const corsOrigins = [...new Set([...configuredCorsOrigins, "https://kidguard-admin-site.vercel.app"])];
app.use(cors({ origin: process.env.CORS_ORIGINS === undefined ? true : corsOrigins }));
app.use(express.json({ limit: "256kb" }));

const firebaseServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) as { project_id?: string; client_email?: string; private_key?: string }
  : undefined;
const firebaseProjectId = process.env.FIREBASE_PROJECT_ID || firebaseServiceAccount?.project_id;
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL || firebaseServiceAccount?.client_email;
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY || firebaseServiceAccount?.private_key;
const sendlibApiKey = process.env.SENDLIB_API_KEY;
const sendlibFromEmail = process.env.SENDLIB_FROM_EMAIL;
const otpHashSecret = process.env.OTP_HASH_SECRET;
const authTokenSecret = process.env.AUTH_TOKEN_SECRET;
const googleClientIds = (process.env.GOOGLE_CLIENT_IDS ?? "").split(",").map(value => value.trim()).filter(Boolean);

if (!getApps().length && firebaseProjectId && firebaseClientEmail && firebasePrivateKey) {
  initializeApp({ credential: cert({
    projectId: firebaseProjectId,
    clientEmail: firebaseClientEmail,
    privateKey: firebasePrivateKey.replace(/\\n/g, "\n"),
  }) });
}

type Principal = { id: string; firebaseUid: string; role: Role; schoolId: string | null; fullName: string; email: string };
declare global { namespace Express { interface Request { principal?: Principal } } }

function publicUser<T extends { id: string; firebaseUid: string; passwordHash?: string | null }>(row: T) {
  const { id, firebaseUid: _firebaseUid, passwordHash: _passwordHash, ...data } = row;
  return { ...data, id: row.firebaseUid, databaseId: id };
}

function asyncRoute(handler: (req: Request, res: Response) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction) => { void handler(req, res).catch(next); };
}

const authenticate = (req: Request, res: Response, next: NextFunction) => {
  void (async () => {
    if (!authTokenSecret || Buffer.byteLength(authTokenSecret) < 32) { res.status(503).json({ error: "PostgreSQL authentication is not configured" }); return; }
    const token = req.header("authorization")?.match(/^Bearer (.+)$/i)?.[1];
    if (!token) { res.status(401).json({ error: "Bearer token required" }); return; }
    try {
      const userId = verifyAccessToken(token);
      if (!userId) { res.status(401).json({ error: "Invalid or expired token" }); return; }
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user || !user.isActive) { res.status(403).json({ error: "Account is not active" }); return; }
      if (user.schoolId) {
        const school = await prisma.school.findUnique({ where: { id: user.schoolId }, select: { isActive: true } });
        if (!school?.isActive) { res.status(403).json({ error: "School access is suspended" }); return; }
      }
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

function signAccessToken(userId: string) {
  if (!authTokenSecret || Buffer.byteLength(authTokenSecret) < 32) throw new Error("AUTH_TOKEN_SECRET must contain at least 32 bytes");
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ sub: userId, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 })).toString("base64url");
  const unsigned = `${header}.${payload}`;
  return `${unsigned}.${createHmac("sha256", authTokenSecret).update(unsigned).digest("base64url")}`;
}

function verifyAccessToken(token: string): string | null {
  if (!authTokenSecret || Buffer.byteLength(authTokenSecret) < 32) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = createHmac("sha256", authTokenSecret).update(unsigned).digest();
  let supplied: Buffer;
  try { supplied = Buffer.from(parts[2], "base64url"); } catch { return null; }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { sub?: unknown; exp?: unknown };
    return typeof payload.sub === "string" && typeof payload.exp === "number" && payload.exp > Date.now() / 1000 ? payload.sub : null;
  } catch { return null; }
}

function hashPassword(password: string) {
  const salt = randomBytes(16).toString("base64url");
  return `${salt}:${scryptSync(password, salt, 64).toString("base64url")}`;
}

function verifyPassword(password: string, encoded: string) {
  const [salt, hash] = encoded.split(":");
  if (!salt || !hash) return false;
  const expected = Buffer.from(hash, "base64url");
  const actual = scryptSync(password, salt, expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function normalizeSafetyTerm(value: string) {
  return value.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().replace(/\s+/g, " ");
}

function requirePlatformAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.principal || req.principal.role !== Role.ADMIN || req.principal.schoolId !== null) {
    res.status(403).json({ error: "Platform administrator access required" });
    return;
  }
  next();
}

async function canAccessChild(user: Principal, childId: string) {
  if (user.role === Role.ADMIN) {
    const child = await prisma.child.findUnique({ where: { id: childId }, select: { schoolId: true } });
    return !!child && (!user.schoolId || child.schoolId === user.schoolId);
  }
  if (user.role === Role.PARENT) return !!await prisma.parentChild.findUnique({ where: { parentId_childId: { parentId: user.id, childId } } });
  return !!await prisma.teacherStudent.findUnique({ where: { teacherId_studentId: { teacherId: user.id, studentId: childId } } });
}

const legacyCollections = new Set(["announcements", "attendance", "behavior_reports", "homework", "homework_submissions", "feedback", "results", "subscriptions", "link_requests"]);

function objectData(value: Prisma.JsonValue): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

async function legacyScope(user: Principal) {
  const links = user.role === Role.PARENT
    ? await prisma.parentChild.findMany({ where: { parentId: user.id }, include: { child: { select: { id: true, schoolId: true, classId: true } } } })
    : user.role === Role.TEACHER
      ? await prisma.teacherStudent.findMany({ where: { teacherId: user.id }, include: { student: { select: { id: true, schoolId: true, classId: true } } } })
      : [];
  const children = links.map(link => "child" in link ? link.child : link.student);
  return {
    childIds: new Set(children.map(child => child.id)),
    classIds: new Set(children.flatMap(child => child.classId ? [child.classId] : [])),
    schoolIds: new Set([...(user.schoolId ? [user.schoolId] : []), ...children.flatMap(child => child.schoolId ? [child.schoolId] : [])]),
    identityIds: new Set([user.id, user.firebaseUid]),
  };
}

function legacyOwner(data: Record<string, unknown>, userId: string) {
  return ["teacherId", "authorId", "createdBy", "userId", "parentId", "submittedBy", "reviewedBy"].some(key => data[key] === userId);
}

async function canReadLegacy(user: Principal, collection: string, data: Record<string, unknown>, scope: Awaited<ReturnType<typeof legacyScope>>) {
  if (user.role === Role.ADMIN) return !user.schoolId || data.schoolId === user.schoolId || !data.schoolId;
  if (legacyOwner(data, user.firebaseUid) || legacyOwner(data, user.id)) return true;
  if (collection === "announcements") {
    if (typeof data.schoolId !== "string" || !scope.schoolIds.has(data.schoolId)) return false;
    const roles = Array.isArray(data.targetRoles) ? data.targetRoles.map(String) : ["all"];
    return roles.some(role => [user.role.toLowerCase(), `${user.role.toLowerCase()}s`, "all", "everyone"].includes(role.toLowerCase()));
  }
  if (collection === "results" && user.role === Role.PARENT && data.isPublished !== true) return false;
  const childId = data.studentId ?? data.childId;
  if (typeof childId === "string") return scope.childIds.has(childId);
  if (typeof data.classId === "string") return scope.classIds.has(data.classId) && (typeof data.schoolId !== "string" || scope.schoolIds.has(data.schoolId));
  return typeof data.schoolId === "string" && scope.schoolIds.has(data.schoolId);
}

async function canWriteLegacy(user: Principal, collection: string, data: Record<string, unknown>, scope: Awaited<ReturnType<typeof legacyScope>>) {
  if (user.role === Role.ADMIN) return !user.schoolId || data.schoolId === user.schoolId;
  if (user.role === Role.TEACHER && ["announcements", "attendance", "behavior_reports", "homework", "results"].includes(collection)) {
    if (data.schoolId !== user.schoolId) return false;
    const studentId = data.studentId ?? data.childId;
    if (typeof studentId === "string") return scope.childIds.has(studentId);
    if (typeof data.classId === "string") return scope.classIds.has(data.classId);
    return collection === "announcements" || collection === "homework";
  }
  if (user.role === Role.PARENT && ["feedback", "homework_submissions", "subscriptions"].includes(collection)) {
    const studentId = data.studentId ?? data.childId;
    return typeof studentId === "string" ? scope.childIds.has(studentId) : collection !== "homework_submissions";
  }
  return false;
}

function hashEmailOtp(email: string, code: string) {
  if (!otpHashSecret) throw new Error("OTP_HASH_SECRET is not configured");
  return createHmac("sha256", otpHashSecret).update(`${email}:${code}`).digest("hex");
}

async function sendTransactionalEmail(email: string, subject: string, text: string, html: string) {
  if (!sendlibApiKey) throw new Error("Sendlib is not configured");
  await sendSendlibEmail({ apiKey: sendlibApiKey, from: sendlibFromEmail, to: email, subject, text, html });
}

function createInvitationToken() {
  const token = randomBytes(32).toString("base64url");
  return { token, tokenHash: createHash("sha256").update(token).digest("hex") };
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[character]!);
}

async function emailSchoolInvitation(email: string, schoolName: string, role: Role, token: string) {
  const roleLabel = role === Role.ADMIN ? "school administrator" : "teacher";
  const safeSchoolName = escapeHtml(schoolName);
  const subject = `Invitation to join ${schoolName} on KidGuard`;
  const text = `You have been invited to join ${schoolName} on KidGuard as a ${roleLabel}. Open KidGuard, choose Join with school invitation, and enter this one-time code: ${token}. The code expires in 7 days. If you were not expecting this invitation, ignore this email.`;
  const safeToken = escapeHtml(token);
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;color:#112442"><h2>Join ${safeSchoolName} on KidGuard</h2><p>You were invited as a ${roleLabel}. In KidGuard, choose <b>Join with school invitation</b> and enter this one-time code:</p><p style="font-size:20px;letter-spacing:2px;font-weight:bold;word-break:break-all;color:#1769e0">${safeToken}</p><p>This invitation expires in 7 days. Ignore this email if you were not expecting it.</p></div>`;
  if (!sendlibApiKey) throw new Error("Sendlib is not configured");
  await sendSendlibEmail({ apiKey: sendlibApiKey, from: sendlibFromEmail, to: email, subject, text, html });
}

app.post("/api/school-access-requests", asyncRoute(async (req, res) => {
  const input = z.object({
    contactName: z.string().trim().min(2).max(160),
    email: z.string().trim().email().max(254).transform(value => value.toLowerCase()),
    phone: z.string().trim().min(6).max(40),
    position: z.string().trim().min(2).max(100),
    schoolName: z.string().trim().min(2).max(160),
    schoolAddress: z.string().trim().min(2).max(300),
    website: z.string().trim().url().max(300).optional().or(z.literal("")),
    studentCount: z.number().int().positive().max(100_000).optional(),
    message: z.string().trim().max(2000).optional(),
  }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const email = input.data.email;
  const recentRequest = await prisma.schoolAccessRequest.findFirst({
    where: { email, status: SchoolRequestStatus.PENDING, createdAt: { gt: new Date(Date.now() - 24 * 60 * 60_000) } },
    select: { id: true },
  });
  if (recentRequest) { res.status(429).json({ error: "A request for this email is already being reviewed" }); return; }
  const request = await prisma.schoolAccessRequest.create({ data: {
    ...input.data,
    website: input.data.website || null,
  } });
  res.status(201).json({ requestId: request.id, status: request.status, message: "Ombi limepokelewa. Timu yetu itawasiliana nawe baada ya kulikagua." });
}));

app.get("/api/admin/school-access-requests", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  if (req.principal!.schoolId) { res.status(403).json({ error: "Only platform administrators can review school requests" }); return; }
  const status = typeof req.query.status === "string" && ["PENDING", "APPROVED", "REJECTED"].includes(req.query.status)
    ? req.query.status as SchoolRequestStatus
    : SchoolRequestStatus.PENDING;
  const requests = await prisma.schoolAccessRequest.findMany({
    where: { status }, orderBy: { createdAt: "asc" },
    include: { school: { select: { id: true, name: true } } },
  });
  res.json({ requests });
}));

app.post("/api/admin/school-access-requests/:requestId/decision", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  if (req.principal!.schoolId) { res.status(403).json({ error: "Only platform administrators can review school requests" }); return; }
  const requestId = req.params.requestId.toString();
  const input = z.object({ decision: z.enum(["approve", "reject"]), reviewNote: z.string().trim().max(1000).optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const request = await prisma.schoolAccessRequest.findUnique({ where: { id: requestId } });
  if (!request || request.status !== SchoolRequestStatus.PENDING) { res.status(404).json({ error: "Pending school request not found" }); return; }

  if (input.data.decision === "reject") {
    const rejected = await prisma.schoolAccessRequest.updateMany({
      where: { id: requestId, status: SchoolRequestStatus.PENDING },
      data: { status: SchoolRequestStatus.REJECTED, reviewerId: req.principal!.id, reviewNote: input.data.reviewNote, reviewedAt: new Date() },
    });
    if (rejected.count !== 1) { res.status(409).json({ error: "This request has already been reviewed" }); return; }
    await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "school_request.reject", entityType: "school_access_request", entityId: requestId } });
    let responseSent = false;
    try {
      const note = input.data.reviewNote?.trim();
      await sendTransactionalEmail(
        request.email,
        `Update on ${request.schoolName}'s KidGuard request`,
        `Thank you for your interest in KidGuard. We are unable to approve ${request.schoolName}'s request at this time.${note ? ` Review note: ${note}` : ""}`,
        `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;color:#112442"><h2>Update on your KidGuard request</h2><p>Thank you for your interest. We are unable to approve ${escapeHtml(request.schoolName)}'s request at this time.</p>${note ? `<p>${escapeHtml(note)}</p>` : ""}</div>`,
      );
      responseSent = true;
    } catch { console.error("School request decision email failed", requestId); }
    res.json({ status: SchoolRequestStatus.REJECTED, responseSent });
    return;
  }

  const invitation = createInvitationToken();
  const approved = await prisma.$transaction(async transaction => {
    await transaction.$queryRaw`SELECT "id" FROM "SchoolAccessRequest" WHERE "id" = ${requestId} FOR UPDATE`;
    const current = await transaction.schoolAccessRequest.findUniqueOrThrow({ where: { id: requestId } });
    if (current.status !== SchoolRequestStatus.PENDING) return null;
    const school = await transaction.school.create({ data: {
      name: current.schoolName,
      address: current.schoolAddress,
      phone: current.phone,
      email: current.email,
      website: current.website ?? undefined,
      principalName: current.contactName,
    } });
    const invite = await transaction.schoolInvitation.create({ data: {
      tokenHash: invitation.tokenHash,
      email: current.email,
      fullName: current.contactName,
      phone: current.phone,
      role: Role.ADMIN,
      schoolId: school.id,
      creatorId: req.principal!.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60_000),
    } });
    await transaction.schoolAccessRequest.update({ where: { id: requestId }, data: {
      status: SchoolRequestStatus.APPROVED,
      reviewerId: req.principal!.id,
      reviewNote: input.data.reviewNote,
      reviewedAt: new Date(),
      schoolId: school.id,
    } });
    await transaction.auditLog.create({ data: { actorId: req.principal!.id, action: "school_request.approve", entityType: "school", entityId: school.id, details: { requestId } } });
    return { school, invite };
  });
  if (!approved) { res.status(409).json({ error: "This request has already been reviewed" }); return; }

  let invitationSent = false;
  try { await emailSchoolInvitation(request.email, approved.school.name, Role.ADMIN, invitation.token); invitationSent = true; }
  catch { console.error("School administrator invitation delivery failed", approved.invite.id); }
  res.status(201).json({ status: SchoolRequestStatus.APPROVED, school: { id: approved.school.id, name: approved.school.name }, invitationId: approved.invite.id, invitationSent });
}));

app.get("/api/platform/invitations", authenticate, requirePlatformAdmin, asyncRoute(async (_req, res) => {
  const invitations = await prisma.schoolInvitation.findMany({
    orderBy: { createdAt: "desc" }, take: 250,
    select: { id: true, email: true, fullName: true, phone: true, role: true, expiresAt: true, usedAt: true, createdAt: true, school: { select: { id: true, name: true, isActive: true } }, creator: { select: { fullName: true, email: true } } },
  });
  res.json({ invitations });
}));
app.get("/api/admin/school-invitations", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const requestedSchoolId = typeof req.query.schoolId === "string" ? req.query.schoolId : undefined;
  const schoolId = req.principal!.schoolId ?? requestedSchoolId;
  if (req.principal!.schoolId && requestedSchoolId && requestedSchoolId !== req.principal!.schoolId) {
    res.status(403).json({ error: "School is outside your authorized scope" }); return;
  }
  const invitations = await prisma.schoolInvitation.findMany({
    where: { role: Role.TEACHER, ...(schoolId ? { schoolId } : {}) },
    orderBy: { createdAt: "desc" }, take: 100,
    select: { id: true, email: true, fullName: true, phone: true, role: true, expiresAt: true, usedAt: true, createdAt: true, school: { select: { id: true, name: true } } },
  });
  res.json({ invitations });
}));
app.post("/api/admin/school-invitations", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().trim().email().max(254).transform(value => value.toLowerCase()), fullName: z.string().trim().min(2).max(160), phone: z.string().trim().max(40).optional(), schoolId: z.string().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const schoolId = req.principal!.schoolId ?? input.data.schoolId;
  if (!schoolId || (req.principal!.schoolId && schoolId !== req.principal!.schoolId)) { res.status(403).json({ error: "Choose a school within your authorized scope" }); return; }
  const school = await prisma.school.findUnique({ where: { id: schoolId }, select: { id: true, name: true } });
  if (!school) { res.status(404).json({ error: "School not found" }); return; }
  const existingMember = await prisma.user.findUnique({ where: { email: input.data.email }, select: { role: true, schoolId: true } });
  if (existingMember && existingMember.schoolId !== schoolId) { res.status(409).json({ error: "This email already belongs to another account or school" }); return; }
  const invitation = createInvitationToken();
  const invite = await prisma.schoolInvitation.create({ data: {
    tokenHash: invitation.tokenHash,
    email: input.data.email,
    fullName: input.data.fullName,
    phone: input.data.phone,
    role: Role.TEACHER,
    schoolId,
    creatorId: req.principal!.id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60_000),
  } });
  try {
    await emailSchoolInvitation(input.data.email, school.name, Role.TEACHER, invitation.token);
  } catch {
    console.error("Teacher invitation delivery failed", invite.id);
    res.status(503).json({ error: "Mwaliko umehifadhiwa lakini email haikutumwa. Kagua SENDLIB_API_KEY na Gmail iliyounganishwa Sendlib kisha ujaribu tena.", invitationId: invite.id });
    return;
  }
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "school_invitation.create", entityType: "school_invitation", entityId: invite.id, details: { role: Role.TEACHER, schoolId } } });
  res.status(201).json({ sent: true });
}));

app.post("/api/admin/school-invitations/:invitationId/resend", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const invitationId = req.params.invitationId.toString();
  const invitation = await prisma.schoolInvitation.findUnique({ where: { id: invitationId }, include: { school: { select: { id: true, name: true } } } });
  if (!invitation || (req.principal!.schoolId && req.principal!.schoolId !== invitation.schoolId)) { res.status(404).json({ error: "Invitation not found" }); return; }
  if (req.principal!.schoolId && invitation.role !== Role.TEACHER) { res.status(404).json({ error: "Invitation not found" }); return; }
  if (invitation.usedAt) { res.status(409).json({ error: "Invitation has already been used" }); return; }
  const newToken = createInvitationToken();
  const updated = await prisma.schoolInvitation.updateMany({ where: { id: invitationId, usedAt: null }, data: { tokenHash: newToken.tokenHash, expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60_000) } });
  if (updated.count !== 1) { res.status(409).json({ error: "Invitation has already been used" }); return; }
  try {
    await emailSchoolInvitation(invitation.email, invitation.school.name, invitation.role, newToken.token);
  } catch {
    console.error("School invitation resend failed", invitation.id);
    res.status(503).json({ error: "Email haikutumwa. Hakikisha SENDLIB_API_KEY na Gmail iliyounganishwa Sendlib zimewekwa kisha ujaribu tena." });
    return;
  }
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "school_invitation.resend", entityType: "school_invitation", entityId: invitation.id, details: { role: invitation.role, schoolId: invitation.schoolId } } });
  res.json({ sent: true });
}));

app.post("/api/school-invitations/claim", asyncRoute(async (req, res) => {
  const input = z.object({ invitationToken: z.string().min(32).max(128), email: z.string().email().max(254), password: z.string().min(10).max(128), fullName: z.string().trim().min(2).max(160).optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const email = input.data.email.trim().toLowerCase();
  const tokenHash = createHash("sha256").update(input.data.invitationToken).digest("hex");
  const result = await prisma.$transaction(async transaction => {
    await transaction.$queryRaw`SELECT "id" FROM "SchoolInvitation" WHERE "tokenHash" = ${tokenHash} FOR UPDATE`;
    const invitation = await transaction.schoolInvitation.findUnique({ where: { tokenHash }, include: { school: { select: { id: true, isActive: true } } } });
    if (!invitation || invitation.usedAt || invitation.expiresAt <= new Date() || invitation.school.isActive !== true || invitation.email.toLowerCase() !== email) return null;
    const existingByEmail = await transaction.user.findUnique({ where: { email } });
    if (existingByEmail && existingByEmail.schoolId && existingByEmail.schoolId !== invitation.schoolId) return null;
    if (existingByEmail?.role === Role.ADMIN && existingByEmail.schoolId === null) return null;
    if (existingByEmail?.passwordHash) return null;
    const user = existingByEmail
      ? await transaction.user.update({ where: { id: existingByEmail.id }, data: { passwordHash: hashPassword(input.data.password), fullName: input.data.fullName || invitation.fullName, phone: invitation.phone ?? existingByEmail.phone, emailVerified: true, role: invitation.role, schoolId: invitation.schoolId, isActive: true } })
      : await transaction.user.create({ data: { firebaseUid: `pg_${randomBytes(20).toString("hex")}`, email, passwordHash: hashPassword(input.data.password), fullName: input.data.fullName || invitation.fullName, phone: invitation.phone, emailVerified: true, role: invitation.role, schoolId: invitation.schoolId } });
    await transaction.schoolInvitation.update({ where: { id: invitation.id }, data: { usedAt: new Date() } });
    await transaction.auditLog.create({ data: { actorId: user.id, action: "school_invitation.claim", entityType: "school", entityId: invitation.schoolId, details: { role: invitation.role } } });
    return { user, role: invitation.role };
  });
  if (!result) { res.status(400).json({ error: "Mwaliko si sahihi, umetumika, au email/akaunti haiendani" }); return; }
  res.json({ joined: true, role: result.role, schoolId: result.user.schoolId, token: signAccessToken(result.user.id), user: publicUser(result.user) });
}));

app.post("/api/auth/email-otp/request", asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()), fullName: z.string().trim().min(1).max(160), phone: z.string().trim().max(40).optional(), purpose: z.enum(["registration", "password_reset"]).default("registration") }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const emailProviderConfigured = !!sendlibApiKey;
  if (!emailProviderConfigured || !otpHashSecret || Buffer.byteLength(otpHashSecret) < 32) { res.status(503).json({ error: "Email verification is not configured" }); return; }
  const { email, fullName, phone } = input.data;
  const existingUser = await prisma.user.findUnique({ where: { email }, select: { emailVerified: true, passwordHash: true, fullName: true } });
  if (input.data.purpose === "registration" && existingUser?.emailVerified && existingUser.passwordHash) { res.status(409).json({ error: "Email is already registered" }); return; }
  if (input.data.purpose === "password_reset" && !existingUser?.passwordHash) { res.status(202).json({ sent: true, expiresInSeconds: 600, resendAfterSeconds: 60 }); return; }
  const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const otpHash = hashEmailOtp(email, code);
  const now = new Date();
  const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  const result = await prisma.$transaction(async transaction => {
    await transaction.emailOtpVerification.upsert({
      where: { email },
      create: { email, otpHash, fullName, phone, attempts: 0, sendsInWindow: 0, sendWindowStartedAt: new Date(0), sentAt: new Date(0), expiresAt: new Date(0) },
      update: {},
    });
    await transaction.$queryRaw`SELECT "email" FROM "EmailOtpVerification" WHERE "email" = ${email} FOR UPDATE`;
    const current = await transaction.emailOtpVerification.findUniqueOrThrow({ where: { email } });
    const cooldownEnds = current.sentAt.getTime() + 60_000;
    if (current.sentAt.getTime() > now.getTime() - 60_000) return { error: "Please wait before requesting another code", retryAfterSeconds: Math.ceil((cooldownEnds - now.getTime()) / 1000) };
    const resetWindow = current.sendWindowStartedAt < hourAgo;
    if (!resetWindow && current.sendsInWindow >= 5) return { error: "Too many codes requested. Try again in an hour", retryAfterSeconds: Math.ceil((current.sendWindowStartedAt.getTime() + 60 * 60 * 1000 - now.getTime()) / 1000) };
    await transaction.emailOtpVerification.update({ where: { email }, data: {
      otpHash, fullName, phone, attempts: 0, sentAt: now,
      expiresAt: new Date(now.getTime() + 10 * 60_000), verifiedAt: null, registrationExpiresAt: null, consumedAt: null,
      sendsInWindow: resetWindow ? 1 : { increment: 1 }, sendWindowStartedAt: resetWindow ? now : current.sendWindowStartedAt,
    } });
    return { sent: true };
  });
  if ("error" in result) { res.status(429).json(result); return; }
  try {
    await sendSendlibOtpEmail({ apiKey: sendlibApiKey!, from: sendlibFromEmail, email, code, name: input.data.purpose === "registration" ? fullName : existingUser?.fullName ?? "KidGuard user" });
  }
  catch {
    await prisma.emailOtpVerification.updateMany({ where: { email, otpHash }, data: { expiresAt: new Date(0), sentAt: new Date(0), otpHash: randomBytes(32).toString("hex") } });
    res.status(503).json({ error: "Could not send the verification email. Try again shortly" }); return;
  }
  res.status(202).json({ sent: true, expiresInSeconds: 600, resendAfterSeconds: 60 });
}));

app.post("/api/auth/email-otp/verify", asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()), code: z.string().regex(/^\d{6}$/) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const { email, code } = input.data;
  const now = new Date();
  const result = await prisma.$transaction(async transaction => {
    const row = await transaction.emailOtpVerification.findUnique({ where: { email } });
    if (!row) return { error: "Verification code is invalid or expired", status: 400 };
    await transaction.$queryRaw`SELECT "email" FROM "EmailOtpVerification" WHERE "email" = ${email} FOR UPDATE`;
    const current = await transaction.emailOtpVerification.findUniqueOrThrow({ where: { email } });
    if (current.verifiedAt && current.registrationExpiresAt && current.registrationExpiresAt > now && !current.consumedAt) return { verified: true };
    if (current.expiresAt <= now || current.consumedAt) return { error: "Verification code is invalid or expired", status: 410 };
    if (current.attempts >= 5) return { error: "Too many incorrect codes. Request a new one", status: 429 };
    const suppliedHash = Buffer.from(hashEmailOtp(email, code), "hex");
    const storedHash = Buffer.from(current.otpHash, "hex");
    if (suppliedHash.length !== storedHash.length || !timingSafeEqual(suppliedHash, storedHash)) {
      const attempts = current.attempts + 1;
      await transaction.emailOtpVerification.update({ where: { email }, data: { attempts } });
      return { error: attempts >= 5 ? "Too many incorrect codes. Request a new one" : "Incorrect verification code", status: attempts >= 5 ? 429 : 400 };
    }
    await transaction.emailOtpVerification.update({ where: { email }, data: { verifiedAt: now, registrationExpiresAt: new Date(now.getTime() + 30 * 60_000), otpHash: randomBytes(32).toString("hex") } });
    return { verified: true };
  });
  if ("error" in result) { res.status(result.status ?? 400).json({ error: result.error }); return; }
  res.json({ verified: true });
}));

app.post("/api/auth/password-reset/confirm", asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()), password: z.string().min(10).max(128) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const now = new Date();
  const user = await prisma.$transaction(async transaction => {
    await transaction.$queryRaw`SELECT "email" FROM "EmailOtpVerification" WHERE "email" = ${input.data.email} FOR UPDATE`;
    const verification = await transaction.emailOtpVerification.findUnique({ where: { email: input.data.email } });
    if (!verification?.verifiedAt || !verification.registrationExpiresAt || verification.registrationExpiresAt <= now || verification.consumedAt) return null;
    const existing = await transaction.user.findUnique({ where: { email: input.data.email } });
    if (!existing?.passwordHash) return null;
    const updated = await transaction.user.update({ where: { id: existing.id }, data: { passwordHash: hashPassword(input.data.password) } });
    await transaction.emailOtpVerification.update({ where: { email: input.data.email }, data: { consumedAt: now } });
    await transaction.auditLog.create({ data: { actorId: updated.id, action: "auth.password_reset", entityType: "user", entityId: updated.id } });
    return updated;
  });
  if (!user) { res.status(400).json({ error: "Verified reset code is missing or expired" }); return; }
  res.json({ reset: true });
}));

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()), password: z.string().min(10).max(128) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const now = new Date();
  const result = await prisma.$transaction(async transaction => {
    await transaction.$queryRaw`SELECT "email" FROM "EmailOtpVerification" WHERE "email" = ${input.data.email} FOR UPDATE`;
    const verification = await transaction.emailOtpVerification.findUnique({ where: { email: input.data.email } });
    if (!verification?.verifiedAt || !verification.registrationExpiresAt || verification.registrationExpiresAt <= now || verification.consumedAt) return null;
    const duplicate = await transaction.user.findUnique({ where: { email: input.data.email } });
    if (duplicate) return null;
    const user = await transaction.user.create({ data: {
      firebaseUid: `pg_${randomBytes(20).toString("hex")}`,
      email: input.data.email, passwordHash: hashPassword(input.data.password),
      fullName: verification.fullName, phone: verification.phone, emailVerified: true, role: Role.PARENT,
    } });
    await transaction.emailOtpVerification.update({ where: { email: input.data.email }, data: { consumedAt: now } });
    await transaction.auditLog.create({ data: { actorId: user.id, action: "auth.self_register", entityType: "user", entityId: user.id } });
    return user;
  });
  if (!result) { res.status(409).json({ error: "Email verification is missing or expired, or this email already has an account" }); return; }
  res.status(201).json({ token: signAccessToken(result.id), user: publicUser(result) });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()), password: z.string().min(1).max(128) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const user = await prisma.user.findUnique({ where: { email: input.data.email } });
  if (!user?.passwordHash) { res.status(401).json({ error: "Account password is not set. Use email verification to migrate this account first." }); return; }
  if (!verifyPassword(input.data.password, user.passwordHash)) { res.status(401).json({ error: "Email or password is incorrect" }); return; }
  if (!user.emailVerified) { res.status(403).json({ error: "Verify your email before signing in" }); return; }
  if (!user.isActive) { res.status(403).json({ error: "This account is disabled" }); return; }
  if (user.schoolId) {
    const school = await prisma.school.findUnique({ where: { id: user.schoolId }, select: { isActive: true } });
    if (!school?.isActive) { res.status(403).json({ error: "School access is suspended" }); return; }
  }
  await prisma.auditLog.create({ data: { actorId: user.id, action: "auth.login", entityType: "user", entityId: user.id } });
  res.json({ token: signAccessToken(user.id), user: publicUser(user) });
}));

app.post("/api/auth/google", asyncRoute(async (req, res) => {
  const input = z.object({ idToken: z.string().min(100).max(8192) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if (!googleClientIds.length) { res.status(503).json({ error: "Google sign-in is not configured" }); return; }
  let payload;
  try {
    payload = (await new OAuth2Client().verifyIdToken({ idToken: input.data.idToken, audience: googleClientIds })).getPayload();
  } catch { res.status(401).json({ error: "Google credential is invalid or expired" }); return; }
  if (!payload?.sub || !payload.email || payload.email_verified !== true) { res.status(401).json({ error: "A verified Google email is required" }); return; }
  const email = payload.email.trim().toLowerCase();
  let user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    user = await prisma.user.create({ data: { firebaseUid: `pg_${randomBytes(20).toString("hex")}`, email, fullName: payload.name || email, profileImageUrl: payload.picture, emailVerified: true, role: Role.PARENT } });
    await prisma.auditLog.create({ data: { actorId: user.id, action: "auth.google_register", entityType: "user", entityId: user.id } });
  } else if (!user.isActive) { res.status(403).json({ error: "This account is disabled" }); return; }
  if (user.schoolId) {
    const school = await prisma.school.findUnique({ where: { id: user.schoolId }, select: { isActive: true } });
    if (!school?.isActive) { res.status(403).json({ error: "School access is suspended" }); return; }
  }
  await prisma.user.update({ where: { id: user.id }, data: { emailVerified: true, profileImageUrl: user.profileImageUrl ?? payload.picture } });
  res.json({ token: signAccessToken(user.id), user: publicUser(user) });
}));

app.post("/api/auth/migrate-password", asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()), password: z.string().min(10).max(128) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const now = new Date();
  const user = await prisma.$transaction(async transaction => {
    await transaction.$queryRaw`SELECT "email" FROM "EmailOtpVerification" WHERE "email" = ${input.data.email} FOR UPDATE`;
    const verification = await transaction.emailOtpVerification.findUnique({ where: { email: input.data.email } });
    if (!verification?.verifiedAt || !verification.registrationExpiresAt || verification.registrationExpiresAt <= now || verification.consumedAt) return null;
    const existing = await transaction.user.findUnique({ where: { email: input.data.email } });
    if (!existing || existing.passwordHash) return null;
    const updated = await transaction.user.update({ where: { id: existing.id }, data: { passwordHash: hashPassword(input.data.password), emailVerified: true } });
    await transaction.emailOtpVerification.update({ where: { email: input.data.email }, data: { consumedAt: now } });
    await transaction.auditLog.create({ data: { actorId: updated.id, action: "auth.password_migrated", entityType: "user", entityId: updated.id } });
    return updated;
  });
  if (!user) { res.status(409).json({ error: "No eligible legacy account or verified email code was found" }); return; }
  res.json({ token: signAccessToken(user.id), user: publicUser(user) });
}));

app.get("/", (_req, res) => res.json({
  name: "KidGuard API",
  status: "ok",
  health: "/health",
}));

app.get("/health", (_req, res) => res.json({ status: "ok", service: "kidguard-api" }));

const aiDefaultSettings = {
  enabled: false, voiceEnabled: true, voiceNotificationsEnabled: true,
  highAlertsEnabled: false, criticalAlertsEnabled: true,
  normalNotificationsEnabled: false, schoolNotificationsEnabled: false,
  homeworkNotificationsEnabled: false, behaviorAlertsEnabled: true, safetyAlertsEnabled: true, language: "sw",
  saveConversations: false,
};
const aiSettingsPatchSchema = z.object({
  enabled: z.boolean().optional(), voiceEnabled: z.boolean().optional(),
  voiceNotificationsEnabled: z.boolean().optional(), highAlertsEnabled: z.boolean().optional(),
  criticalAlertsEnabled: z.boolean().optional(), normalNotificationsEnabled: z.boolean().optional(),
  schoolNotificationsEnabled: z.boolean().optional(), homeworkNotificationsEnabled: z.boolean().optional(),
  behaviorAlertsEnabled: z.boolean().optional(), safetyAlertsEnabled: z.boolean().optional(), saveConversations: z.boolean().optional(), language: z.enum(["sw", "en"]).optional(),
}).strict();

app.get("/api/ai/settings", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const settings = await prisma.aIGuardianSettings.findUnique({ where: { userId: user.id } });
  res.json({ settings: settings ?? aiDefaultSettings });
}));

app.patch("/api/ai/settings", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const parsed = aiSettingsPatchSchema.safeParse(req.body);
  if (!parsed.success || Object.keys(parsed.data).length === 0) { res.status(400).json({ error: "Invalid AI Guardian settings" }); return; }
  const settings = await prisma.aIGuardianSettings.upsert({
    where: { userId: user.id }, create: { userId: user.id, ...parsed.data }, update: parsed.data,
  });
  res.json({ settings });
}));

app.get("/api/ai/conversations", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const conversations = await prisma.aIConversation.findMany({
    where: ownedConversationWhere(user.id), orderBy: { updatedAt: "desc" }, take: 100,
    select: { id: true, title: true, createdAt: true, updatedAt: true, _count: { select: { messages: true } } },
  });
  res.json({ conversations });
}));

app.get("/api/ai/conversations/:conversationId", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const conversation = await prisma.aIConversation.findFirst({
    where: ownedConversationWhere(user.id, req.params.conversationId.toString()),
    select: { id: true, title: true, createdAt: true, updatedAt: true, messages: { orderBy: [{ createdAt: "asc" }, { id: "asc" }], take: 500, select: { role: true, content: true, createdAt: true } } },
  });
  if (!conversation) { res.status(404).json({ error: "Conversation not found" }); return; }
  res.json({ conversation });
}));

app.patch("/api/ai/conversations/:conversationId", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const input = z.object({ title: z.string().trim().min(1).max(80) }).strict().safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: "Conversation title must be 1–80 characters" }); return; }
  const updated = await prisma.aIConversation.updateMany({ where: ownedConversationWhere(user.id, req.params.conversationId.toString()), data: { title: input.data.title } });
  if (!updated.count) { res.status(404).json({ error: "Conversation not found" }); return; }
  res.json({ conversation: await prisma.aIConversation.findFirst({ where: ownedConversationWhere(user.id, req.params.conversationId.toString()), select: { id: true, title: true, updatedAt: true } }) });
}));

app.delete("/api/ai/conversations", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const deleted = await prisma.aIConversation.deleteMany({ where: ownedConversationWhere(user.id) });
  res.json({ deleted: deleted.count });
}));

app.delete("/api/ai/conversations/:conversationId", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const deleted = await prisma.aIConversation.deleteMany({ where: ownedConversationWhere(user.id, req.params.conversationId.toString()) });
  if (!deleted.count) { res.status(404).json({ error: "Conversation not found" }); return; }
  res.json({ deleted: true });
}));

app.post("/api/ai/chat", authenticate, asyncRoute(async (req, res) => {
  const user = req.principal!;
  if (!canUseAiGuardian(user.role, user.schoolId)) { res.status(403).json({ error: "AI Guardian is not available for this account" }); return; }
  const settings = await prisma.aIGuardianSettings.findUnique({ where: { userId: user.id } });
  if (!settings?.enabled) { res.status(403).json({ error: "AI Guardian is disabled" }); return; }
  let conversationId: string | null = null;
  const shouldPersist = settings.saveConversations;
  let userMessage: string | null = null;
  let messages: ReturnType<typeof validateChatMessages> = null;
  if (shouldPersist) {
    const input = z.object({ conversationId: z.string().min(1).max(200).optional(), message: z.string().trim().min(1).max(1000) }).strict().safeParse(req.body);
    if (!input.success) { res.status(400).json({ error: "Send one message of at most 1,000 characters." }); return; }
    userMessage = input.data.message;
    conversationId = input.data.conversationId ?? null;
    if (conversationId) {
      const owned = await prisma.aIConversation.findFirst({ where: ownedConversationWhere(user.id, conversationId), select: { id: true, _count: { select: { messages: true } } } });
      if (!owned) { res.status(404).json({ error: "Conversation not found" }); return; }
      if (owned._count.messages >= 500) { res.status(409).json({ error: "This conversation reached its 500-message limit. Start a new conversation." }); return; }
      const previous = await prisma.aIConversationMessage.findMany({ where: { conversationId: owned.id }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 10, select: { role: true, content: true } });
      messages = buildConversationWindow(previous.reverse().map(item => ({ role: item.role as "user" | "assistant", content: item.content })), userMessage);
    } else {
      messages = [{ role: "user", content: userMessage }];
    }
  } else {
    messages = validateChatMessages(req.body?.messages);
  }
  if (!messages) { res.status(400).json({ error: "Invalid conversation. Keep up to 12 messages and 6,000 characters." }); return; }
  const aiConfiguration = resolveAiAssistantConfiguration(
    process.env.AI_ASSISTANT_HOST,
    process.env.AI_ASSISTANT_SHARED_SECRET,
  );
  if (!aiConfiguration.ok) {
    console.error("KidGuard AI configuration is invalid", { code: aiConfiguration.code });
    res.status(503).json({ error: "KidGuard AI is not configured", code: "ai_not_configured" }); return;
  }
  const { serviceUrl: aiServiceUrl, sharedSecret: aiServiceSecret } = aiConfiguration;
  const now = new Date();
  const bucketStart = new Date(Math.floor(now.getTime() / 60_000) * 60_000);
  const bucket = await prisma.aIGuardianRateLimitBucket.upsert({
    where: { userId_bucketStart: { userId: user.id, bucketStart } },
    create: { userId: user.id, bucketStart, requests: 1 },
    update: { requests: { increment: 1 } },
    select: { requests: true },
  });
  if (bucket.requests > AI_MAX_REQUESTS_PER_MINUTE) { res.status(429).json({ error: "Too many AI requests. Try again in a minute." }); return; }
  void prisma.aIGuardianRateLimitBucket.deleteMany({ where: { bucketStart: { lt: new Date(now.getTime() - 2 * 60 * 60_000) } } }).catch(() => undefined);

  // Build the model context only from records in this authenticated user's scope.
  // Classify the recent user turns together so short follow-ups retain their topic.
  const intent = classifyAiQuestionIntent(messages);
  const summaryIntent = intent.summary;
  const wantsLocation = intent.location;
  const wantsAttendance = intent.attendance;
  const wantsScreenTime = intent.screenTime;
  const wantsHomework = intent.homework;
  const wantsBehavior = intent.behavior;
  const wantsResults = intent.results;
  const wantsSchool = intent.school;
  const wantsDevices = intent.devices;
  const wantsNotifications = intent.notifications;
  const wantsActivity = intent.activity;
  const requestedCollections = [
    ...(wantsAttendance ? ["attendance"] : []),
    ...(wantsBehavior ? ["behavior_reports"] : []),
    ...(wantsHomework ? ["homework", "homework_submissions"] : []),
    ...(wantsResults ? ["results"] : []),
    ...(wantsSchool ? ["announcements"] : []),
  ];
  const needsScopedChildIds = wantsLocation || wantsScreenTime || wantsDevices || wantsActivity || wantsNotifications || wantsSchool || requestedCollections.length > 0;
  const childRows = user.role === Role.PARENT
    ? await prisma.parentChild.findMany({ where: { parentId: user.id }, select: { child: { select: { id: true, fullName: true, schoolId: true } } } })
    : user.role === Role.TEACHER
      ? await prisma.teacherStudent.findMany({ where: { teacherId: user.id }, select: { student: { select: { id: true, fullName: true, schoolId: true } } } })
      : needsScopedChildIds
        ? await prisma.child.findMany({ where: { schoolId: user.schoolId!, isActive: true }, select: { id: true, fullName: true, schoolId: true } })
        : [];
  const children = childRows.map((row: any) => "child" in row ? row.child : "student" in row ? row.student : row);
  const childIds = children.map((child: { id: string }) => child.id);
  const childLabels = new Map(children.map((child: { id: string; fullName: string }, index: number) => [child.id, cleanContextText(child.fullName.split(/\s+/)[0], 40) ?? `Mtoto ${index + 1}`]));
  const aliases = new Set(childIds);
  const scope = user.role === Role.ADMIN ? null : await legacyScope(user);
  const authorizedSchoolIds = [...new Set([user.schoolId, ...children.map((child: { schoolId: string | null }) => child.schoolId)].filter((id): id is string => !!id))];
  const schools = wantsSchool && authorizedSchoolIds.length ? await prisma.school.findMany({ where: { id: { in: authorizedSchoolIds }, isActive: true }, select: { name: true, motto: true } }) : [];
  const locations = wantsLocation && childIds.length ? await prisma.deviceLocation.findMany({
    where: { childId: { in: childIds } }, orderBy: { timestamp: "desc" }, distinct: ["childId"], take: 50,
    select: { childId: true, placeName: true, timestamp: true },
  }) : [];
  const screenTimes = wantsScreenTime && childIds.length ? await prisma.screenTimeRecord.findMany({
    where: { childId: { in: childIds }, date: { gte: new Date(Date.now() - 7 * 86400_000) } },
    orderBy: { date: "desc" }, distinct: ["childId", "date"], take: 70,
    select: { childId: true, date: true, totalMinutes: true, unlockedCount: true, appUsage: true },
  }) : [];
  const devices = wantsDevices && childIds.length ? await prisma.device.findMany({
    where: { childId: { in: childIds }, isAuthorized: true }, orderBy: { lastSeen: "desc" }, distinct: ["childId"],
    select: { childId: true, lastSeen: true },
  }) : [];
  const recentNotifications = wantsNotifications ? await prisma.notification.findMany({
    where: { recipientId: user.id, OR: [{ childId: null }, { childId: { in: childIds } }], createdAt: { gte: new Date(Date.now() - 30 * 86400_000) } }, orderBy: { createdAt: "desc" }, take: 20,
    select: { title: true, body: true, type: true, priority: true, createdAt: true, childId: true, payload: true },
  }) : [];
  const recentActivity = wantsActivity && childIds.length ? await prisma.deviceActivityEvent.findMany({
    where: { childId: { in: childIds }, createdAt: { gte: new Date(Date.now() - 7 * 86400_000) } },
    orderBy: { createdAt: "desc" }, take: 60,
    select: { childId: true, type: true, payload: true, createdAt: true },
  }) : [];
  const contextRecords: Array<Record<string, unknown>> = [];
  for (const collection of requestedCollections) {
    if (contextRecords.length >= 60) break;
    const rows = await prisma.legacyRecord.findMany({ where: { collection }, orderBy: { updatedAt: "desc" }, take: 300, select: { data: true } });
    for (const row of rows) {
      const data = objectData(row.data);
      const recordChildId = data.studentId ?? data.childId;
      const announcementRoleAllowed = (Array.isArray(data.targetRoles) ? data.targetRoles.map(String) : ["all"])
        .some(role => [user.role.toLowerCase(), `${user.role.toLowerCase()}s`, "all", "everyone"].includes(role.toLowerCase()));
      const authorized = user.role === Role.ADMIN
        ? data.schoolId === user.schoolId && (collection !== "announcements" || announcementRoleAllowed)
        : collection === "announcements"
          ? typeof data.schoolId === "string" && scope!.schoolIds.has(data.schoolId) && announcementRoleAllowed
          : typeof recordChildId === "string" ? aliases.has(recordChildId)
            : typeof data.classId === "string" && scope!.classIds.has(data.classId) && typeof data.schoolId === "string" && scope!.schoolIds.has(data.schoolId);
      if (!authorized || (collection === "results" && user.role === Role.PARENT && data.isPublished !== true)) continue;
      const item: Record<string, unknown> = { category: collection };
      const alias = typeof recordChildId === "string" ? childLabels.get(recordChildId) : undefined;
      if (alias) item.child = alias;
      for (const key of ["date", "createdAt", "status", "subject", "title", "score", "grade", "present", "minutes", "totalMinutes", "dueDate", "isPublished"]) {
        const value = data[key];
        if (typeof value === "string") item[key] = cleanContextText(value, 80);
        else if (typeof value === "number" || typeof value === "boolean") item[key] = value;
      }
      contextRecords.push(item);
      if (contextRecords.length >= 60) break;
    }
  }
  const context = {
    role: user.role === Role.ADMIN ? "school administrator" : user.role.toLowerCase(),
    schools: schools.map(school => ({ name: cleanContextText(school.name, 100), motto: cleanContextText(school.motto, 120) })),
    childCount: user.role === Role.ADMIN && (wantsAttendance || summaryIntent) ? await prisma.child.count({ where: { schoolId: user.schoolId!, isActive: true } }) : children.length,
    children: (wantsLocation || wantsScreenTime || wantsDevices || requestedCollections.length > 0 ? children : []).slice(0, 30).map((child: { id: string }, index: number) => ({
      label: childLabels.get(child.id) ?? `Mtoto ${index + 1}`,
      lastLocation: locations.find(location => location.childId === child.id)
        ? (() => { const point = locations.find(location => location.childId === child.id)!; return { place: cleanContextText(point.placeName), observedAt: point.timestamp.toISOString() }; })()
        : null,
      recentScreenTime: screenTimes.filter(item => item.childId === child.id).slice(0, 7).map(item => {
        const appUsage = objectData(item.appUsage);
        const apps = Object.entries(appUsage).flatMap(([key, raw]) => {
          if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
          const row = raw as Record<string, unknown>;
          const minutes = Number(row.minutesUsed ?? row.minutes ?? 0);
          if (!Number.isFinite(minutes) || minutes <= 0) return [];
          const appName = cleanContextText(row.appName ?? key, 60);
          return appName ? [{ app: appName, minutes: Math.round(minutes) }] : [];
        }).sort((a, b) => b.minutes - a.minutes).slice(0, 5);
        return { date: new Intl.DateTimeFormat("en-CA", { timeZone: "Africa/Nairobi", year: "numeric", month: "2-digit", day: "2-digit" }).format(item.date), minutes: item.totalMinutes, unlocks: item.unlockedCount, apps };
      }),
      deviceStatus: (() => { const device = devices.find(item => item.childId === child.id); return device ? { status: device.lastSeen && device.lastSeen.getTime() >= Date.now() - 35 * 60_000 ? "ONLINE" : "OFFLINE", lastSeen: device.lastSeen?.toISOString() ?? null } : null; })(),
    })),
    recentNotifications: recentNotifications.map(item => {
      const payload = objectData(item.payload);
      const label = item.childId ? childLabels.get(item.childId) : undefined;
      return {
        ...(label ? { child: label } : {}),
        title: cleanContextText(item.title, 120),
        summary: cleanContextText(item.body, 300),
        category: cleanContextText(item.type, 50),
        priority: cleanContextText(item.priority, 20),
        riskCategory: cleanContextText(payload.riskCategory, 40),
        riskSeverity: cleanContextText(payload.riskSeverity, 20),
        generatedReason: cleanContextText(payload.explanation, 240),
        createdAt: item.createdAt.toISOString(),
      };
    }),
    recentActivity: recentActivity.map(event => {
      const payload = objectData(event.payload);
      const childLabel = event.childId ? childLabels.get(event.childId) : undefined;
      const entry: Record<string, unknown> = {
        ...(childLabel ? { child: childLabel } : {}),
        type: cleanContextText(event.type, 50),
        occurredAt: event.createdAt.toISOString(),
      };
      if (event.type === "blocked_content") {
        entry.riskCategory = cleanContextText(payload.riskCategory, 40) ?? "unsafe_content";
        entry.riskSeverity = cleanContextText(payload.riskSeverity, 20);
        entry.reason = cleanContextText(payload.explanation, 240) ?? "A configured safety rule matched.";
      } else if (event.type === "app_usage_summary") {
        const rows = Array.isArray(payload.apps) ? payload.apps : [];
        entry.apps = rows.slice(0, 8).flatMap(raw => {
          if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
          const row = raw as Record<string, unknown>;
          const name = cleanContextText(row.appName ?? row.packageName, 60);
          const minutes = Number(row.minutesUsed ?? row.minutes ?? 0);
          return name && Number.isFinite(minutes) && minutes >= 0 ? [{ app: name, minutes: Math.round(minutes) }] : [];
        });
      } else if (event.type === "device_heartbeat") {
        entry.monitoringActive = payload.monitoringActive === true;
        entry.accessibilityActive = payload.accessibilityActive === true;
        entry.usageAccessActive = payload.usageAccessActive === true;
      } else if (event.type === "tamper_event") {
        entry.reason = cleanContextText(payload.message, 160) ?? "Device protection status changed.";
      }
      return entry;
    }),
    records: contextRecords,
  };
  let answer: string;
  try {
    answer = await requestAiAssistant({ serviceUrl: aiServiceUrl, sharedSecret: aiServiceSecret, messages, context: boundAiContext(context), language: settings.language });
  } catch (error) {
    if (error instanceof AiAssistantRequestError) {
      console.error("KidGuard AI provider failure", { code: error.code, status: error.providerStatus });
      const status = ["assistant_auth_failed", "assistant_bad_request", "assistant_rate_limited"].includes(error.code) ? 503 : 502;
      const errorText = error.code === "assistant_auth_failed" ? "AI assistant authentication failed"
        : error.code === "assistant_rate_limited" ? "AI assistant quota or rate limit reached"
        : error.code === "assistant_bad_request" ? "AI assistant rejected the request"
        : error.code === "assistant_network_error" || error.code === "assistant_timeout" ? "AI assistant connection failed"
        : "AI assistant returned an unavailable or invalid response";
      res.status(status).json({ error: errorText, code: error.code });
      return;
    }
    console.error("KidGuard AI request failed", { category: error instanceof Error ? error.name : "unknown" });
    res.status(502).json({ error: "KidGuard AI haipatikani kwa sasa. Tafadhali jaribu tena.", code: "assistant_request_failed" });
    return;
  }
  if (shouldPersist && userMessage) {
    try {
      const saved = await prisma.$transaction(async transaction => {
        let ownedId = conversationId;
        if (ownedId) {
          const stillOwned = await transaction.aIConversation.findFirst({ where: ownedConversationWhere(user.id, ownedId), select: { id: true } });
          if (!stillOwned) throw new Error("Conversation not found");
        } else {
          const count = await transaction.aIConversation.count({ where: { userId: user.id } });
          if (count >= 100) throw new Error("Conversation limit reached");
          const conversation = await transaction.aIConversation.create({ data: { userId: user.id, title: cleanContextText(userMessage, 60) ?? "Mazungumzo mapya" }, select: { id: true } });
          ownedId = conversation.id;
        }
        await transaction.aIConversationMessage.create({ data: { conversationId: ownedId!, role: "user", content: userMessage } });
        await transaction.aIConversationMessage.create({ data: { conversationId: ownedId!, role: "assistant", content: answer } });
        await transaction.aIConversation.update({ where: { id: ownedId! }, data: { updatedAt: new Date() } });
        return ownedId!;
      });
      res.json({ answer, conversationId: saved, saved: true });
    } catch (error) {
      if (error instanceof Error && error.message === "Conversation not found") { res.status(404).json({ error: "Conversation not found" }); return; }
      if (error instanceof Error && error.message === "Conversation limit reached") { res.status(409).json({ error: "Delete a saved conversation before starting another." }); return; }
      res.status(500).json({ error: "The answer was generated but could not be saved. Please retry." });
    }
    return;
  }
  res.json({ answer, conversationId: null, saved: false });
}));

app.get("/api/records/:collection", authenticate, asyncRoute(async (req, res) => {
  const collection = req.params.collection.toString();
  if (!legacyCollections.has(collection)) { res.status(404).json({ error: "Record collection not found" }); return; }
  const scope = await legacyScope(req.principal!);
  const requestedStudent = typeof req.query.studentId === "string" ? req.query.studentId : undefined;
  if (requestedStudent && !scope.childIds.has(requestedStudent) && req.principal!.role !== Role.ADMIN) { res.status(403).json({ error: "Student is outside your authorized scope" }); return; }
  const limit = Math.min(500, Math.max(1, Number.parseInt(String(req.query.limit ?? "200"), 10) || 200));
  const records = await prisma.legacyRecord.findMany({ where: { collection }, orderBy: { updatedAt: "desc" }, take: 2000 });
  const rows = [];
  for (const record of records) {
    const data = objectData(record.data);
    if (requestedStudent && (data.studentId ?? data.childId) !== requestedStudent) continue;
    if (typeof req.query.classId === "string" && data.classId !== req.query.classId) continue;
    if (!await canReadLegacy(req.principal!, collection, data, scope)) continue;
    rows.push({ id: record.sourceId, ...data });
    if (rows.length >= limit) break;
  }
  res.json({ records: rows });
}));

app.post("/api/records/:collection", authenticate, asyncRoute(async (req, res) => {
  const collection = req.params.collection.toString();
  if (!legacyCollections.has(collection)) { res.status(404).json({ error: "Record collection not found" }); return; }
  const input = z.record(z.unknown()).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const user = req.principal!;
  const scope = await legacyScope(user);
  const data: Record<string, unknown> = { ...input.data };
  delete data.id;
  if (user.role === Role.TEACHER) { data.teacherId = user.firebaseUid; data.authorId ??= user.firebaseUid; data.schoolId = user.schoolId; }
  if (user.role === Role.PARENT) {
    if (collection === "homework_submissions") data.studentId = typeof input.data.studentId === "string" ? input.data.studentId : undefined;
    else data.parentId = user.firebaseUid;
    if (collection === "feedback") data.userId = user.firebaseUid;
  }
  if (!await canWriteLegacy(user, collection, data, scope)) { res.status(403).json({ error: "You cannot create this record" }); return; }
  const id = `legacy_${randomBytes(18).toString("hex")}`;
  const record = await prisma.legacyRecord.create({ data: { collection, sourceId: id, data: data as Prisma.InputJsonValue } });
  res.status(201).json({ record: { id: record.sourceId, ...data } });
}));

app.patch("/api/records/:collection/:recordId", authenticate, asyncRoute(async (req, res) => {
  const collection = req.params.collection.toString();
  if (!legacyCollections.has(collection)) { res.status(404).json({ error: "Record collection not found" }); return; }
  const input = z.record(z.unknown()).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const record = await prisma.legacyRecord.findUnique({ where: { collection_sourceId: { collection, sourceId: req.params.recordId.toString() } } });
  if (!record) { res.status(404).json({ error: "Record not found" }); return; }
  const user = req.principal!;
  const scope = await legacyScope(user);
  const oldData = objectData(record.data);
  const readOnlyMark = collection === "announcements" && Object.keys(input.data).every(key => key === "readBy") && await canReadLegacy(user, collection, oldData, scope);
  if (!readOnlyMark && !await canWriteLegacy(user, collection, oldData, scope)) { res.status(403).json({ error: "You cannot update this record" }); return; }
  const merged = { ...oldData, ...input.data };
  if (readOnlyMark) {
    const readBy = Array.isArray(oldData.readBy) ? oldData.readBy.map(String) : [];
    merged.readBy = [...new Set([...readBy, user.firebaseUid])];
  }
  const updated = await prisma.legacyRecord.update({ where: { collection_sourceId: { collection, sourceId: record.sourceId } }, data: { data: merged as Prisma.InputJsonValue } });
  res.json({ record: { id: updated.sourceId, ...merged } });
}));

app.delete("/api/records/:collection/:recordId", authenticate, asyncRoute(async (req, res) => {
  const collection = req.params.collection.toString();
  if (!legacyCollections.has(collection)) { res.status(404).json({ error: "Record collection not found" }); return; }
  const record = await prisma.legacyRecord.findUnique({ where: { collection_sourceId: { collection, sourceId: req.params.recordId.toString() } } });
  if (!record) { res.status(204).end(); return; }
  const scope = await legacyScope(req.principal!);
  if (req.principal!.role !== Role.ADMIN || (req.principal!.schoolId && objectData(record.data).schoolId !== req.principal!.schoolId)) { res.status(403).json({ error: "Only an authorized administrator can delete this record" }); return; }
  await prisma.legacyRecord.delete({ where: { collection_sourceId: { collection, sourceId: record.sourceId } } });
  void scope;
  res.status(204).end();
}));

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

app.get("/api/platform/overview", authenticate, requirePlatformAdmin, asyncRoute(async (_req, res) => {
  const now = new Date();
  const currentHour = new Date(now);
  currentHour.setUTCHours(currentHour.getUTCHours(), 0, 0, 0);
  const since = new Date(currentHour.getTime() - 23 * 60 * 60_000);
  const [users, parents, teachers, admins, schools, activeSchools, students, devices, activeDevices, events24h, audit24h, unreadNotifications, pendingSchoolRequests] = await Promise.all([
    prisma.user.count(),
    prisma.user.count({ where: { role: Role.PARENT, isActive: true } }),
    prisma.user.count({ where: { role: Role.TEACHER, isActive: true } }),
    prisma.user.count({ where: { role: Role.ADMIN, schoolId: null, isActive: true } }),
    prisma.school.count(),
    prisma.school.count({ where: { isActive: true } }),
    prisma.child.count(),
    prisma.device.count(),
    prisma.device.count({ where: { isAuthorized: true } }),
    prisma.deviceActivityEvent.count({ where: { createdAt: { gte: since } } }),
    prisma.auditLog.count({ where: { createdAt: { gte: since } } }),
    prisma.notification.count({ where: { isRead: false } }),
    prisma.schoolAccessRequest.count({ where: { status: SchoolRequestStatus.PENDING } }),
  ]);
  const [eventHours, auditHours] = await Promise.all([
    prisma.$queryRaw<{ bucket: Date; total: bigint }[]>`SELECT date_trunc('hour', "createdAt") AS bucket, COUNT(*) AS total FROM "DeviceActivityEvent" WHERE "createdAt" >= ${since} GROUP BY bucket ORDER BY bucket`,
    prisma.$queryRaw<{ bucket: Date; total: bigint }[]>`SELECT date_trunc('hour', "createdAt") AS bucket, COUNT(*) AS total FROM "AuditLog" WHERE "createdAt" >= ${since} GROUP BY bucket ORDER BY bucket`,
  ]);
  const hourMap = new Map<string, { events: number; audits: number }>();
  for (let offset = 0; offset < 24; offset++) {
    const bucket = new Date(since.getTime() + offset * 60 * 60_000).toISOString();
    hourMap.set(bucket, { events: 0, audits: 0 });
  }
  for (const row of eventHours) {
    const bucket = new Date(row.bucket).toISOString();
    const current = hourMap.get(bucket);
    if (current) current.events = Number(row.total);
  }
  for (const row of auditHours) {
    const bucket = new Date(row.bucket).toISOString();
    const current = hourMap.get(bucket);
    if (current) current.audits = Number(row.total);
  }
  res.json({ generatedAt: now.toISOString(), activityByHour: [...hourMap.entries()].map(([hour, totals]) => ({ hour, ...totals })), counts: { users, parents, teachers, platformAdmins: admins, schools, activeSchools, students, devices, activeDevices, events24h, audit24h, unreadNotifications, pendingSchoolRequests } });
}));

app.get("/api/platform/users/:firebaseUid", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const firebaseUid = req.params.firebaseUid.toString();
  const user = await prisma.user.findUnique({
    where: { firebaseUid },
    include: {
      school: { select: { id: true, name: true, isActive: true } },
      children: { include: { child: { include: { school: { select: { id: true, name: true } }, classroom: { select: { id: true, name: true } }, _count: { select: { devices: true, activityEvents: true } } } } } },
      taught: { include: { student: { include: { school: { select: { id: true, name: true } }, classroom: { select: { id: true, name: true } }, _count: { select: { devices: true, activityEvents: true } } } } } },
      devices: { select: { id: true, name: true, model: true, platform: true, appVersion: true, status: true, isAuthorized: true, lastSeen: true, createdAt: true } },
      _count: { select: { children: true, taught: true, devices: true, notifications: true } },
    },
  });
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  const [notifications, auditLogs] = await Promise.all([
    prisma.notification.findMany({ where: { recipientId: user.id }, orderBy: { createdAt: "desc" }, take: 20, select: { id: true, title: true, body: true, type: true, isRead: true, createdAt: true } }),
    prisma.auditLog.findMany({ where: { entityId: user.id }, orderBy: { createdAt: "desc" }, take: 20, include: { actor: { select: { fullName: true, email: true } } } }),
  ]);
  const { children, taught, devices, _count, ...profile } = user;
  res.json({
    user: { ...publicUser(profile), linkedChildrenCount: _count.children, taughtStudentsCount: _count.taught, devicesCount: _count.devices, notificationsCount: _count.notifications },
    children: children.map(link => ({ ...link.child, devicesCount: link.child._count.devices, activityCount: link.child._count.activityEvents })),
    taughtStudents: taught.map(link => ({ ...link.student, devicesCount: link.student._count.devices, activityCount: link.student._count.activityEvents })),
    devices, notifications, auditLogs,
  });
}));

app.get("/api/platform/users", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 100) : "";
  const role = typeof req.query.role === "string" && Object.values(Role).includes(req.query.role as Role) ? req.query.role as Role : undefined;
  const schoolId = typeof req.query.schoolId === "string" ? req.query.schoolId : undefined;
  const page = Math.max(1, Number.parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(String(req.query.pageSize ?? "50"), 10) || 50));
  const where: Prisma.UserWhereInput = {
    ...(role ? { role } : {}), ...(schoolId ? { schoolId } : {}),
    ...(search ? { OR: [{ email: { contains: search, mode: "insensitive" } }, { fullName: { contains: search, mode: "insensitive" } }, { phone: { contains: search, mode: "insensitive" } }] } : {}),
  };
  const [total, rows] = await Promise.all([
    prisma.user.count({ where }),
    prisma.user.findMany({ where, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize, include: { school: { select: { id: true, name: true, isActive: true } }, _count: { select: { children: true, taught: true, devices: true } } } }),
  ]);
  res.json({ page, pageSize, total, users: rows.map(row => ({ ...publicUser(row), linkedChildrenCount: row._count.children, taughtStudentsCount: row._count.taught, devicesCount: row._count.devices })) });
}));

app.patch("/api/platform/users/:firebaseUid", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const firebaseUid = req.params.firebaseUid.toString();
  const input = z.object({
    role: z.nativeEnum(Role).optional(),
    schoolId: z.string().nullable().optional(),
    isActive: z.boolean().optional(),
    fullName: z.string().trim().min(2).max(160).optional(),
    phone: z.string().trim().max(40).nullable().optional(),
  }).refine(value => Object.keys(value).length > 0).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const target = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!target) { res.status(404).json({ error: "User not found" }); return; }
  const newRole = input.data.role ?? target.role;
  const newSchoolId = input.data.schoolId === undefined ? target.schoolId : input.data.schoolId;
  const newIsActive = input.data.isActive ?? target.isActive;
  if (newSchoolId && !await prisma.school.findUnique({ where: { id: newSchoolId }, select: { id: true } })) { res.status(400).json({ error: "School not found" }); return; }
  const targetIsGlobalAdmin = target.role === Role.ADMIN && target.schoolId === null && target.isActive;
  const remainsGlobalAdmin = newRole === Role.ADMIN && newSchoolId === null && newIsActive;
  if (targetIsGlobalAdmin && !remainsGlobalAdmin) {
    const activeGlobalAdmins = await prisma.user.count({ where: { role: Role.ADMIN, schoolId: null, isActive: true } });
    if (activeGlobalAdmins <= 1) { res.status(409).json({ error: "Cannot remove the last active platform administrator" }); return; }
  }
  const updated = await prisma.user.update({ where: { firebaseUid }, data: { ...input.data } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "platform.user.update", entityType: "user", entityId: updated.id, details: { changedFields: Object.keys(input.data), role: updated.role, schoolId: updated.schoolId, isActive: updated.isActive } } });
  res.json({ user: publicUser(updated) });
}));

app.get("/api/platform/schools", authenticate, requirePlatformAdmin, asyncRoute(async (_req, res) => {
  const schools = await prisma.school.findMany({ orderBy: { createdAt: "desc" }, include: { _count: { select: { users: true, children: true, devices: true, classes: true } } } });
  res.json({ schools: schools.map(({ _count, settings: _settings, ...school }) => ({ ...school, usersCount: _count.users, studentsCount: _count.children, devicesCount: _count.devices, classesCount: _count.classes })) });
}));

app.patch("/api/platform/schools/:schoolId", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const schoolId = req.params.schoolId.toString();
  const input = z.object({ isActive: z.boolean().optional(), name: z.string().trim().min(2).max(160).optional() }).refine(value => Object.keys(value).length > 0).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const school = await prisma.school.update({ where: { id: schoolId }, data: input.data });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "platform.school.update", entityType: "school", entityId: school.id, details: input.data } });
  res.json({ school });
}));

app.get("/api/platform/students", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 100) : "";
  const page = Math.max(1, Number.parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(String(req.query.pageSize ?? "50"), 10) || 50));
  const where: Prisma.ChildWhereInput = search ? { OR: [{ fullName: { contains: search, mode: "insensitive" } }, { className: { contains: search, mode: "insensitive" } }] } : {};
  const [total, students] = await Promise.all([
    prisma.child.count({ where }),
    prisma.child.findMany({ where, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize, include: { school: { select: { id: true, name: true } }, classroom: { select: { id: true, name: true } }, parents: { include: { parent: { select: { fullName: true, email: true } } } }, teachers: { include: { teacher: { select: { fullName: true, email: true } } } }, _count: { select: { devices: true, activityEvents: true } } } }),
  ]);
  res.json({ page, pageSize, total, students: students.map(student => ({ id: student.id, fullName: student.fullName, className: student.className, isActive: student.isActive, createdAt: student.createdAt, school: student.school, classroom: student.classroom, parents: student.parents.map(link => link.parent), teachers: student.teachers.map(link => link.teacher), devicesCount: student._count.devices, activityCount: student._count.activityEvents })) });
}));

app.get("/api/platform/students/:studentId", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const studentId = req.params.studentId.toString();
  const [student, activity, locations, screenTime] = await Promise.all([
    prisma.child.findUnique({ where: { id: studentId }, include: { school: { select: { id: true, name: true } }, classroom: { select: { id: true, name: true } }, parents: { include: { parent: { select: { fullName: true, email: true, phone: true } } } }, teachers: { include: { teacher: { select: { fullName: true, email: true, phone: true } } } }, devices: { select: { id: true, name: true, platform: true, status: true, isAuthorized: true, lastSeen: true } } } }),
    prisma.deviceActivityEvent.findMany({ where: { childId: studentId }, orderBy: { createdAt: "desc" }, take: 50, include: { device: { select: { name: true, platform: true } } } }),
    prisma.deviceLocation.findMany({ where: { childId: studentId }, orderBy: { timestamp: "desc" }, take: 50, select: { latitude: true, longitude: true, accuracy: true, address: true, placeName: true, timestamp: true } }),
    prisma.screenTimeRecord.findMany({ where: { childId: studentId }, orderBy: { date: "desc" }, take: 30, select: { date: true, totalMinutes: true, unlockedCount: true, appUsage: true } }),
  ]);
  if (!student) { res.status(404).json({ error: "Student not found" }); return; }
  res.json({ student, activity, locations, screenTime });
}));

app.get("/api/platform/devices", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 100) : "";
  const page = Math.max(1, Number.parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(String(req.query.pageSize ?? "50"), 10) || 50));
  const where: Prisma.DeviceWhereInput = search ? { OR: [{ name: { contains: search, mode: "insensitive" } }, { model: { contains: search, mode: "insensitive" } }, { child: { fullName: { contains: search, mode: "insensitive" } } }] } : {};
  const [total, devices] = await Promise.all([
    prisma.device.count({ where }),
    prisma.device.findMany({ where, orderBy: { updatedAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize, select: { id: true, name: true, model: true, platform: true, osVersion: true, appVersion: true, status: true, lastSeen: true, isAuthorized: true, batteryLevel: true, isCharging: true, storageUsed: true, storageTotal: true, memoryUsed: true, memoryTotal: true, createdAt: true, updatedAt: true, school: { select: { id: true, name: true } }, child: { select: { id: true, fullName: true } }, owner: { select: { fullName: true, email: true } } } }),
  ]);
  res.json({ page, pageSize, total, devices });
}));

app.patch("/api/platform/devices/:deviceId/revoke", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const deviceId = req.params.deviceId.toString();
  const existing = await prisma.device.findUnique({ where: { id: deviceId }, select: { id: true } });
  if (!existing) { res.status(404).json({ error: "Device not found" }); return; }
  await prisma.$transaction(async transaction => {
    await transaction.device.update({ where: { id: deviceId }, data: { isAuthorized: false, status: "OFFLINE", fcmToken: null, deviceSecretHash: null } });
    await transaction.deviceRegistration.updateMany({ where: { deviceId }, data: { authorized: false } });
    await transaction.deviceLinkToken.deleteMany({ where: { deviceId } });
    await transaction.auditLog.create({ data: { actorId: req.principal!.id, action: "platform.device.revoke", entityType: "device", entityId: deviceId } });
  });
  res.json({ revoked: true });
}));

app.get("/api/platform/activity", authenticate, requirePlatformAdmin, asyncRoute(async (_req, res) => {
  const [auditLogs, deviceEvents] = await Promise.all([
    prisma.auditLog.findMany({ orderBy: { createdAt: "desc" }, take: 100, include: { actor: { select: { fullName: true, email: true, role: true } } } }),
    prisma.deviceActivityEvent.findMany({ orderBy: { createdAt: "desc" }, take: 100, include: { child: { select: { id: true, fullName: true } }, device: { select: { id: true, name: true, platform: true } } } }),
  ]);
  res.json({ auditLogs, deviceEvents });
}));

app.get("/api/platform/firestore-data", authenticate, requirePlatformAdmin, asyncRoute(async (req, res) => {
  const collections = ["announcements", "attendance", "behavior_reports", "feedback", "homework", "homework_submissions", "results", "subscriptions", "link_requests"] as const;
  const collection = typeof req.query.collection === "string" ? req.query.collection : "";
  if (!collections.includes(collection as typeof collections[number])) { res.status(400).json({ error: "Unsupported app data collection" }); return; }
  const limit = Math.min(200, Math.max(1, Number.parseInt(String(req.query.limit ?? "100"), 10) || 100));
  const records = await prisma.legacyRecord.findMany({ where: { collection }, orderBy: { createdAt: "desc" }, take: limit });
  res.json({ collection, count: records.length, rows: records.map(record => ({ id: record.sourceId, data: record.data })) });
}));

app.get("/api/platform/security", authenticate, requirePlatformAdmin, asyncRoute(async (_req, res) => {
  const now = new Date();
  const dayAgo = new Date(now.getTime() - 24 * 60 * 60_000);
  const [inactiveUsers, unverifiedUsers, suspendedSchools, unauthorizedOnlineDevices, expiredInvitations, recentSecurityAudit] = await Promise.all([
    prisma.user.count({ where: { isActive: false } }),
    prisma.user.count({ where: { emailVerified: false } }),
    prisma.school.count({ where: { isActive: false } }),
    prisma.device.count({ where: { isAuthorized: false, status: "ONLINE" } }),
    prisma.schoolInvitation.count({ where: { usedAt: null, expiresAt: { lt: now } } }),
    prisma.auditLog.findMany({ where: { createdAt: { gte: dayAgo }, OR: [ { action: { contains: "auth", mode: "insensitive" } }, { action: { contains: "account", mode: "insensitive" } }, { action: { contains: "device", mode: "insensitive" } }, { action: { contains: "user", mode: "insensitive" } }, { action: { contains: "school", mode: "insensitive" } } ] }, orderBy: { createdAt: "desc" }, take: 100, include: { actor: { select: { fullName: true, email: true, role: true } } } }),
  ]);
  res.json({ generatedAt: now.toISOString(), counts: { inactiveUsers, unverifiedUsers, suspendedSchools, unauthorizedOnlineDevices, expiredInvitations }, recentSecurityAudit });
}));

app.post("/api/auth/sync", (_req, res) => res.status(410).json({ error: "Firebase identity sync is retired. Sign in with the PostgreSQL API." }));

app.post("/api/admin/users", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const input = z.object({ firebaseUid: z.string().min(1).optional(), email: z.string().email(), password: z.string().min(10).max(128), fullName: z.string().trim().min(1).max(160), role: z.enum(["PARENT", "TEACHER"]), phone: z.string().max(40).optional(), schoolId: z.string().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const value = input.data;
  const schoolId = value.schoolId ?? req.principal!.schoolId ?? undefined;
  if (req.principal!.schoolId && schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  const normalizedEmail = value.email.trim().toLowerCase();
  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  const user = existing
    ? await prisma.user.update({ where: { id: existing.id }, data: { fullName: value.fullName, phone: value.phone, emailVerified: true, role: value.role, schoolId, ...(!existing.passwordHash ? { passwordHash: hashPassword(value.password) } : {}) } })
    : await prisma.user.create({ data: { firebaseUid: value.firebaseUid ?? `pg_${randomBytes(20).toString("hex")}`, email: normalizedEmail, passwordHash: hashPassword(value.password), fullName: value.fullName, phone: value.phone, emailVerified: true, role: value.role, schoolId } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "user.provision", entityType: "user", entityId: user.id, details: { role: user.role, schoolId: user.schoolId } } });
  res.status(201).json({ id: user.id, role: user.role });
}));

app.get("/api/me", authenticate, asyncRoute(async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.principal!.id }, include: { children: { select: { childId: true } }, taught: { select: { studentId: true } } } });
  res.json({ user: { ...publicUser(user), childrenIds: user.children.map(row => row.childId), studentIds: user.taught.map(row => row.studentId), parentIds: [] } });
}));

app.post("/api/me/email-otp/request", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if (!sendlibApiKey || !otpHashSecret || Buffer.byteLength(otpHashSecret) < 32) { res.status(503).json({ error: "Email verification is not configured" }); return; }
  const { id: userId, email: currentEmail } = req.principal!;
  const email = input.data.email;
  if (email === currentEmail.toLowerCase()) { res.status(400).json({ error: "Enter a different email address" }); return; }
  if (await prisma.user.findUnique({ where: { email }, select: { id: true } })) { res.status(409).json({ error: "Email is already registered" }); return; }

  const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const otpHash = hashEmailOtp(email, code);
  const now = new Date();
  const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  let result;
  try {
    result = await prisma.$transaction(async transaction => {
      await transaction.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${userId}))`;
      const current = await transaction.emailChangeVerification.findUnique({ where: { userId } });
      const cooldownEnds = current ? current.sentAt.getTime() + 60_000 : 0;
      if (current && current.sentAt.getTime() > now.getTime() - 60_000) return { error: "Please wait before requesting another code", retryAfterSeconds: Math.ceil((cooldownEnds - now.getTime()) / 1000) };
      const resetWindow = !current || current.sendWindowStartedAt < hourAgo;
      if (current && !resetWindow && current.sendsInWindow >= 5) return { error: "Too many codes requested. Try again in an hour", retryAfterSeconds: Math.ceil((current.sendWindowStartedAt.getTime() + 60 * 60 * 1000 - now.getTime()) / 1000) };
      if (current) {
        await transaction.emailChangeVerification.update({ where: { userId }, data: { email, otpHash, attempts: 0, sentAt: now, expiresAt: new Date(now.getTime() + 10 * 60_000), sendsInWindow: resetWindow ? 1 : { increment: 1 }, sendWindowStartedAt: resetWindow ? now : current.sendWindowStartedAt } });
      } else {
        await transaction.emailChangeVerification.create({ data: { userId, email, otpHash, attempts: 0, sendsInWindow: 1, sendWindowStartedAt: now, sentAt: now, expiresAt: new Date(now.getTime() + 10 * 60_000) } });
      }
      return { sent: true };
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") { res.status(409).json({ error: "Email is already registered or a verification is pending" }); return; }
    throw error;
  }
  if ("error" in result) { res.status(429).json(result); return; }
  try {
    await sendSendlibOtpEmail({ apiKey: sendlibApiKey, from: sendlibFromEmail, email, code, name: req.principal!.fullName });
  } catch {
    await prisma.emailChangeVerification.updateMany({ where: { userId, email, otpHash }, data: { expiresAt: new Date(0), sentAt: new Date(0), otpHash: randomBytes(32).toString("hex") } });
    res.status(503).json({ error: "Could not send the verification email. Try again shortly" }); return;
  }
  res.status(202).json({ sent: true, expiresInSeconds: 600, resendAfterSeconds: 60 });
}));

app.post("/api/me/email-otp/verify", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().email().max(254).transform(value => value.trim().toLowerCase()), code: z.string().regex(/^\d{6}$/) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const { id: userId } = req.principal!;
  const { email, code } = input.data;
  const now = new Date();
  let result;
  try {
    result = await prisma.$transaction(async transaction => {
      await transaction.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${userId}))`;
      const current = await transaction.emailChangeVerification.findUnique({ where: { userId } });
      if (!current || current.email !== email || current.expiresAt <= now) return { error: "Verification code is invalid or expired", status: 410 };
      if (current.attempts >= 5) return { error: "Too many incorrect codes. Request a new one", status: 429 };
      const suppliedHash = Buffer.from(hashEmailOtp(email, code), "hex");
      const storedHash = Buffer.from(current.otpHash, "hex");
      if (suppliedHash.length !== storedHash.length || !timingSafeEqual(suppliedHash, storedHash)) {
        const attempts = current.attempts + 1;
        await transaction.emailChangeVerification.update({ where: { userId }, data: { attempts } });
        return { error: attempts >= 5 ? "Too many incorrect codes. Request a new one" : "Incorrect verification code", status: attempts >= 5 ? 429 : 400 };
      }
      const collision = await transaction.user.findUnique({ where: { email }, select: { id: true } });
      if (collision && collision.id !== userId) return { error: "Email is already registered", status: 409 };
      const user = await transaction.user.update({ where: { id: userId }, data: { email, emailVerified: true } });
      await transaction.emailChangeVerification.delete({ where: { userId } });
      await transaction.auditLog.create({ data: { actorId: userId, action: "user.email_changed", entityType: "user", entityId: userId } });
      return { user };
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") { res.status(409).json({ error: "Email is already registered" }); return; }
    throw error;
  }
  if ("error" in result) { res.status(result.status ?? 400).json({ error: result.error }); return; }
  res.json({ verified: true, user: publicUser(result.user) });
}));

app.patch("/api/me", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ fullName: z.string().trim().min(1).max(160).optional(), phone: z.string().max(40).nullable().optional(), profileImageUrl: z.string().url().nullable().optional(), preferences: z.record(z.unknown()).optional(), isPremium: z.boolean().optional(), premiumExpiry: z.string().datetime().nullable().optional() }).strict().safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if ((input.data.isPremium !== undefined || input.data.premiumExpiry !== undefined) && req.principal!.role !== Role.ADMIN) { res.status(403).json({ error: "Premium status requires administrator authorization" }); return; }
  const { preferences, premiumExpiry, ...fields } = input.data;
  const user = await prisma.user.update({ where: { id: req.principal!.id }, data: { ...fields, ...(preferences ? { preferences: preferences as Prisma.InputJsonValue } : {}), ...(premiumExpiry !== undefined ? { premiumExpiry: premiumExpiry ? new Date(premiumExpiry) : null } : {}) } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "user.profile_update", entityType: "user", entityId: user.id } });
  res.json({ user: publicUser(user) });
}));

app.delete("/api/me", authenticate, asyncRoute(async (req, res) => {
  const { id, firebaseUid } = req.principal!;
  const firebaseUidHash = createHash("sha256").update(firebaseUid).digest("hex");
  await prisma.$transaction(async transaction => {
    await transaction.deletedAuthIdentity.upsert({ where: { firebaseUidHash }, create: { firebaseUidHash }, update: {} });
    await transaction.emailOtpVerification.deleteMany({ where: { email: req.principal!.email.toLowerCase() } });
    // Remove the migrated Firestore account snapshot for this identity as well.
    await transaction.legacyRecord.deleteMany({ where: { collection: "users_unmapped", sourceId: firebaseUid } });

    const registrations = await transaction.deviceRegistration.findMany({ where: { actorId: id }, select: { deviceId: true } });
    await transaction.deviceRegistration.deleteMany({ where: { actorId: id } });
    await transaction.deviceLinkToken.deleteMany({ where: { actorId: id } });
    for (const { deviceId } of registrations) {
      const remaining = await transaction.deviceRegistration.count({ where: { deviceId, authorized: true } });
      if (!remaining) await transaction.device.updateMany({ where: { id: deviceId, ownerId: null }, data: { isAuthorized: false, status: "OFFLINE", fcmToken: null, deviceSecretHash: null } });
    }

    const ownedDevices = await transaction.device.findMany({ where: { ownerId: id }, select: { id: true, childId: true } });
    for (const device of ownedDevices) {
      const otherAuthorizedRegistration = await transaction.deviceRegistration.count({ where: { deviceId: device.id, actorId: { not: id }, authorized: true } });
      if (!device.childId) {
        await transaction.device.delete({ where: { id: device.id } });
      } else if (otherAuthorizedRegistration) {
        await transaction.device.update({ where: { id: device.id }, data: { ownerId: null, fcmToken: null } });
      } else {
        // Monitoring history belongs to this parent's now-unshared device link.
        await transaction.deviceActivityEvent.deleteMany({ where: { deviceId: device.id } });
        await transaction.deviceLocation.deleteMany({ where: { deviceId: device.id } });
        await transaction.screenTimeRecord.deleteMany({ where: { deviceId: device.id } });
        await transaction.device.update({ where: { id: device.id }, data: { ownerId: null, isAuthorized: false, status: "OFFLINE", fcmToken: null, deviceSecretHash: null } });
      }
    }

    await transaction.auditLog.create({ data: { action: "user.account_delete", entityType: "user", details: { firebaseUidHash } } });
    await transaction.user.delete({ where: { id } });
  });
  res.status(204).end();
}));

app.get("/api/admin/users", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const role = typeof req.query.role === "string" && ["ADMIN", "TEACHER", "PARENT"].includes(req.query.role) ? req.query.role as Role : undefined;
  const schoolId = typeof req.query.schoolId === "string" ? req.query.schoolId : req.principal!.schoolId ?? undefined;
  if (req.principal!.schoolId && schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "School is outside your authorized scope" }); return; }
  const includeInactive = req.query.includeInactive === "true";
  const users = await prisma.user.findMany({ where: { ...(role ? { role } : {}), ...(schoolId ? { schoolId } : {}), ...(!includeInactive ? { isActive: true } : {}) }, include: { children: { select: { childId: true } }, taught: { select: { studentId: true } } }, orderBy: { fullName: "asc" } });
  res.json({ users: users.map(user => ({ ...publicUser(user), childrenIds: user.children.map(row => row.childId), studentIds: user.taught.map(row => row.studentId) })) });
}));

app.patch("/api/admin/users/:firebaseUid/access", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const input = z.object({ isActive: z.boolean() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const firebaseUid = req.params.firebaseUid.toString();
  const user = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!user || user.role !== Role.TEACHER || (req.principal!.schoolId && user.schoolId !== req.principal!.schoolId)) {
    res.status(404).json({ error: "Teacher not found in your school" }); return;
  }
  const updated = await prisma.user.update({ where: { id: user.id }, data: { isActive: input.data.isActive } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: input.data.isActive ? "teacher.activate" : "teacher.suspend", entityType: "user", entityId: updated.id, details: { schoolId: updated.schoolId } } });
  res.json({ id: updated.firebaseUid, isActive: updated.isActive });
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
  if (!child || !teacher || teacher.role !== Role.TEACHER || !teacher.isActive || !child.schoolId || child.schoolId !== teacher.schoolId) { res.status(404).json({ error: "Child or teacher not found in the same school" }); return; }
  if (req.principal!.schoolId && (child.schoolId !== req.principal!.schoolId || teacher.schoolId !== req.principal!.schoolId)) { res.status(403).json({ error: "Child or teacher is outside your school" }); return; }
  await prisma.teacherStudent.upsert({ where: { teacherId_studentId: { teacherId: teacher.id, studentId: child.id } }, create: { teacherId: teacher.id, studentId: child.id }, update: {} });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.teacher_link", entityType: "child", entityId: child.id, details: { teacherId: teacher.id } } });
  res.json({ success: true });
}));

app.delete("/api/admin/children/:childId/teachers/:teacherFirebaseUid", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  const teacherFirebaseUid = req.params.teacherFirebaseUid.toString();
  const [child, teacher] = await Promise.all([
    prisma.child.findUnique({ where: { id: childId }, select: { id: true, schoolId: true } }),
    prisma.user.findUnique({ where: { firebaseUid: teacherFirebaseUid }, select: { id: true, firebaseUid: true, role: true, schoolId: true } }),
  ]);
  if (!child || !teacher || teacher.role !== Role.TEACHER || !child.schoolId || child.schoolId !== teacher.schoolId) {
    res.status(404).json({ error: "Child or teacher not found in the same school" }); return;
  }
  if (req.principal!.schoolId && (child.schoolId !== req.principal!.schoolId || teacher.schoolId !== req.principal!.schoolId)) {
    res.status(403).json({ error: "Child or teacher is outside your school" }); return;
  }
  const removed = await prisma.teacherStudent.deleteMany({ where: { teacherId: teacher.id, studentId: child.id } });
  if (removed.count) await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.teacher_unlink", entityType: "child", entityId: child.id, details: { teacherId: teacher.firebaseUid } } });
  res.json({ success: true, removed: removed.count === 1 });
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
  const input = z.object({ id: z.string().min(1).max(200), childCode: z.string().min(4).max(128).optional(), fullName: z.string().trim().min(1).max(160), schoolId: z.string().optional(), className: z.string().max(80).optional() }).safeParse(req.body);
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
  const child = await prisma.child.upsert({ where: { id: input.data.id }, create: { id: input.data.id, linkCode: input.data.childCode, fullName: input.data.fullName, schoolId, className: input.data.className, classId: schoolClass?.id }, update: { linkCode: input.data.childCode, fullName: input.data.fullName, schoolId, className: input.data.className, classId: schoolClass?.id } });
  if (user.role === Role.PARENT) await prisma.parentChild.upsert({ where: { parentId_childId: { parentId: user.id, childId: child.id } }, create: { parentId: user.id, childId: child.id }, update: {} });
  if (user.role === Role.TEACHER) await prisma.teacherStudent.upsert({ where: { teacherId_studentId: { teacherId: user.id, studentId: child.id } }, create: { teacherId: user.id, studentId: child.id }, update: {} });
  await prisma.auditLog.create({ data: { actorId: user.id, action: "child.register", entityType: "child", entityId: child.id } });
  res.status(201).json({ child });
}));

app.post("/api/children/link", authenticate, allow(Role.PARENT), asyncRoute(async (req, res) => {
  const input = z.object({ childCode: z.string().trim().min(4).max(128), childName: z.string().trim().min(1).max(160) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const child = await prisma.child.findFirst({ where: { linkCode: input.data.childCode, fullName: { equals: input.data.childName, mode: "insensitive" }, isActive: true } });
  if (!child) { res.status(404).json({ error: "Child not found. Check the pairing code and name." }); return; }
  await prisma.parentChild.upsert({ where: { parentId_childId: { parentId: req.principal!.id, childId: child.id } }, create: { parentId: req.principal!.id, childId: child.id }, update: {} });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.link_by_code", entityType: "child", entityId: child.id } });
  res.json({ child });
}));

app.post("/api/children/link-requests", authenticate, allow(Role.PARENT), asyncRoute(async (req, res) => {
  const input = z.object({ childId: z.string().min(1), childName: z.string().trim().min(1).max(160) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const child = await prisma.child.findUnique({ where: { id: input.data.childId } });
  if (!child || child.fullName.toLowerCase() !== input.data.childName.toLowerCase()) { res.status(404).json({ error: "Child profile not found" }); return; }
  const sourceId = `link_${randomBytes(18).toString("hex")}`;
  await prisma.legacyRecord.create({ data: { collection: "link_requests", sourceId, data: { parentId: req.principal!.firebaseUid, parentDatabaseId: req.principal!.id, parentName: req.principal!.fullName, childId: child.id, childName: child.fullName, schoolId: child.schoolId, status: "pending", createdAt: new Date().toISOString() } } });
  res.status(201).json({ requestId: sourceId, status: "pending" });
}));

app.get("/api/admin/children/link-requests", authenticate, allow(Role.ADMIN), asyncRoute(async (req, res) => {
  const rows = await prisma.legacyRecord.findMany({ where: { collection: "link_requests" }, orderBy: { createdAt: "desc" }, take: 300 });
  const requests = rows.filter(row => {
    const data = objectData(row.data);
    return data.status === "pending" && (!req.principal!.schoolId || data.schoolId === req.principal!.schoolId);
  }).map(row => ({ id: row.sourceId, ...objectData(row.data) }));
  res.json({ requests });
}));

app.post("/api/admin/children/link-requests/:requestId/approve", authenticate, allow(Role.ADMIN, Role.TEACHER), asyncRoute(async (req, res) => {
  const requestId = req.params.requestId.toString();
  const row = await prisma.legacyRecord.findUnique({ where: { collection_sourceId: { collection: "link_requests", sourceId: requestId } } });
  if (!row) { res.status(404).json({ error: "Link request not found" }); return; }
  const data = objectData(row.data);
  if (req.principal!.schoolId && data.schoolId !== req.principal!.schoolId) { res.status(403).json({ error: "Request is outside your school" }); return; }
  if (data.status !== "pending" || typeof data.childId !== "string") { res.status(409).json({ error: "Request is no longer pending" }); return; }
  if (req.principal!.role === Role.TEACHER && !await canAccessChild(req.principal!, data.childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  const parentDatabaseId = typeof data.parentDatabaseId === "string" ? data.parentDatabaseId : typeof data.parentId === "string" ? (await prisma.user.findUnique({ where: { firebaseUid: data.parentId }, select: { id: true } }))?.id : undefined;
  if (!parentDatabaseId) { res.status(409).json({ error: "Requesting parent account is unavailable" }); return; }
  const childId = data.childId;
  const parent = await prisma.user.findUnique({ where: { id: parentDatabaseId }, select: { isActive: true } });
  const child = await prisma.child.findUnique({ where: { id: childId }, select: { id: true } });
  if (!parent?.isActive || !child) { res.status(409).json({ error: "Parent or child profile is no longer active" }); return; }
  await prisma.$transaction([
    prisma.parentChild.upsert({ where: { parentId_childId: { parentId: parentDatabaseId, childId } }, create: { parentId: parentDatabaseId, childId }, update: {} }),
    prisma.legacyRecord.update({ where: { collection_sourceId: { collection: "link_requests", sourceId: requestId } }, data: { data: { ...data, parentDatabaseId, status: "approved", reviewedBy: req.principal!.firebaseUid, reviewedAt: new Date().toISOString() } as Prisma.InputJsonValue } }),
    prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.link_request.approve", entityType: "child", entityId: childId } }),
  ]);
  res.json({ approved: true });
}));

app.delete("/api/children/:childId/link", authenticate, allow(Role.PARENT, Role.TEACHER), asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  const user = req.principal!;
  if (!await canAccessChild(user, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  await prisma.$transaction(async transaction => {
    if (user.role === Role.PARENT) await transaction.parentChild.delete({ where: { parentId_childId: { parentId: user.id, childId } } });
    else await transaction.teacherStudent.delete({ where: { teacherId_studentId: { teacherId: user.id, studentId: childId } } });

    await transaction.deviceLinkToken.deleteMany({ where: { actorId: user.id, childId } });
    const registrations = await transaction.deviceRegistration.findMany({ where: { actorId: user.id, device: { childId } }, select: { deviceId: true } });
    await transaction.deviceRegistration.deleteMany({ where: { actorId: user.id, device: { childId } } });
    const ownedDevices = await transaction.device.findMany({ where: { childId, ownerId: user.id }, select: { id: true } });
    const affectedDeviceIds = new Set([...registrations.map(row => row.deviceId), ...ownedDevices.map(row => row.id)]);
    for (const deviceId of affectedDeviceIds) {
      const remaining = await transaction.deviceRegistration.count({ where: { deviceId, authorized: true } });
      if (remaining) await transaction.device.updateMany({ where: { id: deviceId, ownerId: user.id }, data: { ownerId: null } });
      else await transaction.device.updateMany({ where: { id: deviceId, OR: [{ ownerId: user.id }, { ownerId: null }] }, data: { ownerId: null, isAuthorized: false, status: "OFFLINE", fcmToken: null, deviceSecretHash: null } });
    }
    await transaction.auditLog.create({ data: { actorId: user.id, action: "child.unlink", entityType: "child", entityId: childId } });
  });
  res.status(204).end();
}));

app.post("/api/device-links", authenticate, allow(Role.ADMIN, Role.TEACHER, Role.PARENT), asyncRoute(async (req, res) => {
  const input = z.object({ childId: z.string().min(1), validForMinutes: z.number().int().min(1).max(120).default(120) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const user = req.principal!;
  if (!await canAccessChild(user, input.data.childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  if (user.role === Role.PARENT) {
    const count = await prisma.device.count({ where: { child: { parents: { some: { parentId: user.id } } }, isAuthorized: true } });
    if (count >= 5) { res.status(409).json({ error: "Parent device limit reached" }); return; }
  }
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + input.data.validForMinutes * 60_000);
  await prisma.deviceLinkToken.create({ data: { tokenHash: createHash("sha256").update(token).digest("hex"), childId: input.data.childId, actorId: user.id, expiresAt } });
  res.status(201).json({ token, expiresAt: expiresAt.toISOString() });
}));

// A valid short-lived QR token can reveal only the authorized account email and child label for pairing.
app.post("/api/device-links/preview", asyncRoute(async (req, res) => {
  const input = z.object({ token: z.string().min(20).max(200) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: "Invalid pairing token" }); return; }
  const tokenHash = createHash("sha256").update(input.data.token).digest("hex");
  const link = await prisma.deviceLinkToken.findUnique({ where: { tokenHash } });
  if (!link || link.usedAt || link.expiresAt <= new Date()) { res.status(410).json({ error: "Pairing token is invalid, expired, or already used" }); return; }
  const [actor, child] = await Promise.all([
    prisma.user.findUnique({ where: { id: link.actorId }, select: { email: true, isActive: true } }),
    prisma.child.findUnique({ where: { id: link.childId }, select: { fullName: true } }),
  ]);
  if (!actor?.isActive || !child) { res.status(410).json({ error: "Pairing is no longer available" }); return; }
  res.json({ email: actor.email, childName: child.fullName, expiresAt: link.expiresAt.toISOString() });
}));

app.get("/api/children/:childId/safety-terms", authenticate, allow(Role.PARENT), asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found" }); return; }
  const terms = await prisma.childSafetyTerm.findMany({ where: { childId }, orderBy: { createdAt: "asc" }, select: { id: true, term: true, enabled: true, createdAt: true } });
  res.json({ terms });
}));

app.post("/api/children/:childId/safety-terms", authenticate, allow(Role.PARENT), asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  const input = z.object({ term: z.string().trim().min(2).max(80) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found" }); return; }
  const existingCount = await prisma.childSafetyTerm.count({ where: { childId } });
  if (existingCount >= 100) { res.status(409).json({ error: "Maximum of 100 parent-defined terms reached" }); return; }
  const normalizedTerm = normalizeSafetyTerm(input.data.term);
  if (normalizedTerm.length < 2) { res.status(400).json({ error: "Term must contain searchable letters or numbers" }); return; }
  try {
    const term = await prisma.childSafetyTerm.create({ data: { childId, createdById: req.principal!.id, term: input.data.term, normalizedTerm }, select: { id: true, term: true, enabled: true, createdAt: true } });
    await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.safety_term.add", entityType: "child", entityId: childId } });
    res.status(201).json({ term });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") { res.status(409).json({ error: "That term is already on the list" }); return; }
    throw error;
  }
}));

app.delete("/api/children/:childId/safety-terms/:termId", authenticate, allow(Role.PARENT), asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  const termId = req.params.termId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found" }); return; }
  const deleted = await prisma.childSafetyTerm.deleteMany({ where: { id: termId, childId } });
  if (deleted.count) await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "child.safety_term.remove", entityType: "child", entityId: childId } });
  res.json({ deleted: deleted.count === 1 });
}));

// A one-use, short-lived QR token authorizes a child device to pair without a child account.
app.post("/api/device-links/register", authenticate, allow(Role.ADMIN, Role.TEACHER, Role.PARENT), asyncRoute(async (req, res) => {
  const input = z.object({ token: z.string().min(20).max(200), deviceKey: z.string().min(1).max(200), deviceSecret: z.string().min(24).max(200), platform: z.enum(["ANDROID", "IOS", "WINDOWS", "MACOS", "WEB"]), name: z.string().min(1).max(120), model: z.string().max(120).optional(), osVersion: z.string().max(120).optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const value = input.data;
  const tokenHash = createHash("sha256").update(value.token).digest("hex");
  const device = await prisma.$transaction(async transaction => {
    const now = new Date();
    const link = await transaction.deviceLinkToken.findUnique({ where: { tokenHash } });
    if (!link || link.usedAt || link.expiresAt <= now || link.actorId !== req.principal!.id) return null;
    const actor = await transaction.user.findUnique({ where: { id: link.actorId }, select: { id: true, role: true, schoolId: true, isActive: true, firebaseUid: true } });
    if (!actor?.isActive) return null;
    const childAccess = actor.role === Role.PARENT
      ? await transaction.parentChild.findUnique({ where: { parentId_childId: { parentId: actor.id, childId: link.childId } }, select: { parentId: true } })
      : actor.role === Role.TEACHER
        ? await transaction.teacherStudent.findUnique({ where: { teacherId_studentId: { teacherId: actor.id, studentId: link.childId } }, select: { teacherId: true } })
        : await transaction.child.findFirst({ where: { id: link.childId, ...(actor.schoolId ? { schoolId: actor.schoolId } : {}) }, select: { id: true } });
    if (!childAccess) return null;
    const claimed = await transaction.deviceLinkToken.updateMany({ where: { tokenHash, usedAt: null, expiresAt: { gt: now } }, data: { usedAt: now } });
    if (!claimed.count) return null;
    const child = await transaction.child.findUnique({ where: { id: link.childId }, select: { schoolId: true } });
    if (!child) return null;
    const result = await transaction.device.create({ data: { deviceKey: value.deviceKey, childId: link.childId, schoolId: child.schoolId, ownerId: link.actorId, platform: value.platform, name: value.name, model: value.model, osVersion: value.osVersion, deviceSecretHash: createHash("sha256").update(value.deviceSecret).digest("hex"), status: "ONLINE", isAuthorized: true, lastSeen: new Date() } });
    await transaction.deviceRegistration.create({ data: { deviceId: result.id, actorId: link.actorId, authorized: true } });
    await transaction.deviceLinkToken.update({ where: { tokenHash }, data: { deviceId: result.id } });
    return { device: result, childId: link.childId, ownerId: actor.id };
  });
  if (!device) { res.status(410).json({ error: "Pairing token is invalid, expired, or already used" }); return; }
  res.status(201).json({ id: device.device.id, childId: device.childId, parentId: device.ownerId, status: device.device.status });
}));

app.post("/api/device-monitoring/config", asyncRoute(async (req, res) => {
  const input = z.object({ deviceId: z.string().min(1), childId: z.string().min(1), deviceSecret: z.string().min(24).max(200) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: "Invalid device credentials" }); return; }
  const device = await prisma.device.findUnique({ where: { id: input.data.deviceId } });
  if (!device || !device.isAuthorized || device.childId !== input.data.childId || !device.deviceSecretHash) { res.status(403).json({ error: "Device registration is invalid" }); return; }
  const actualHash = Buffer.from(createHash("sha256").update(input.data.deviceSecret).digest("hex"), "hex");
  const expectedHash = Buffer.from(device.deviceSecretHash, "hex");
  if (actualHash.length !== expectedHash.length || !timingSafeEqual(actualHash, expectedHash)) { res.status(403).json({ error: "Device credentials are invalid" }); return; }
  const terms = await prisma.childSafetyTerm.findMany({ where: { childId: device.childId, enabled: true }, select: { term: true, normalizedTerm: true }, take: 100 });
  res.json({ terms });
}));

app.post("/api/device-events", asyncRoute(async (req, res) => {
  const input = z.object({ deviceId: z.string().min(1), childId: z.string().min(1), deviceSecret: z.string().min(24).max(200), type: z.enum(["blocked_content", "app_usage_summary", "tamper_event", "device_heartbeat", "location_update"]), payload: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const event = input.data;
  const device = await prisma.device.findUnique({ where: { id: event.deviceId } });
  if (!device || !device.isAuthorized || device.childId !== event.childId || !device.ownerId || !device.deviceSecretHash) { res.status(403).json({ error: "Device registration is invalid" }); return; }
  const actualHash = Buffer.from(createHash("sha256").update(event.deviceSecret).digest("hex"), "hex");
  const expectedHash = Buffer.from(device.deviceSecretHash, "hex");
  if (actualHash.length !== expectedHash.length || !timingSafeEqual(actualHash, expectedHash)) { res.status(403).json({ error: "Device credentials are invalid" }); return; }
  const createdAt = new Date();
  if (event.type === "location_update") {
    const location = z.object({ latitude: z.number().min(-90).max(90), longitude: z.number().min(-180).max(180), accuracy: z.number().nonnegative().max(100_000), timestamp: z.number().int().positive() }).safeParse(event.payload);
    if (!location.success || !device.ownerId) { res.status(400).json({ error: "Invalid location report" }); return; }
    const previous = await prisma.deviceLocation.findFirst({ where: { deviceId: device.id }, orderBy: { timestamp: "desc" }, select: { timestamp: true } });
    if (previous && createdAt.getTime() - previous.timestamp.getTime() < 5 * 60 * 1000) { res.status(202).json({ accepted: true, rateLimited: true }); return; }
    const timestamp = new Date(location.data.timestamp);
    if (Math.abs(createdAt.getTime() - timestamp.getTime()) > 10 * 60 * 1000) { res.status(400).json({ error: "Location timestamp is stale" }); return; }
    await prisma.$transaction([
      prisma.deviceLocation.create({ data: { deviceId: device.id, childId: device.childId!, latitude: location.data.latitude, longitude: location.data.longitude, accuracy: location.data.accuracy, timestamp, retentionClass: "child_gps_v1" } }),
      prisma.device.update({ where: { id: device.id }, data: { status: "ONLINE", lastSeen: createdAt } }),
    ]);
    res.status(202).json({ accepted: true });
    return;
  }
  let storedPayload = event.payload as Record<string, unknown>;
  let riskCategory: string | undefined;
  let riskSeverity: string | undefined;
  let riskDedupKey: string | undefined;
  if (event.type === "blocked_content" && typeof event.payload.riskCategory === "string") {
    const category = z.enum(["self_harm", "threat", "bullying", "unsafe_content"]).safeParse(event.payload.riskCategory);
    const severity = z.enum(["low", "medium", "high", "urgent"]).safeParse(event.payload.riskSeverity);
    const dedupKey = z.string().regex(/^[a-f0-9]{64}$/).safeParse(event.payload.dedupKey);
    if (!category.success || !severity.success || !dedupKey.success) { res.status(400).json({ error: "Invalid risk event metadata" }); return; }
    riskCategory = category.data;
    riskSeverity = severity.data;
    riskDedupKey = dedupKey.data;
    const duplicate = await prisma.deviceActivityEvent.findFirst({
      where: { deviceId: device.id, type: "blocked_content", createdAt: { gte: new Date(createdAt.getTime() - 15 * 60 * 1000) }, payload: { path: ["dedupKey"], equals: riskDedupKey } },
      select: { id: true },
    });
    if (duplicate) { res.status(202).json({ accepted: true, duplicate: true }); return; }
    if (riskSeverity === "medium" || riskSeverity === "low") {
      const recentAlerts = await prisma.deviceActivityEvent.count({
        where: { deviceId: device.id, type: "blocked_content", createdAt: { gte: new Date(createdAt.getTime() - 60 * 1000) } },
      });
      if (recentAlerts >= 5) { res.status(202).json({ accepted: false, rateLimited: true }); return; }
    }
    const ruleIds = Array.isArray(event.payload.ruleIds)
      ? event.payload.ruleIds.filter((value): value is string => typeof value === "string").slice(0, 5).map(value => value.slice(0, 80))
      : [];
    const packageName = typeof event.payload.packageName === "string" ? event.payload.packageName.slice(0, 180) : "";
    const explanation = typeof event.payload.explanation === "string" ? event.payload.explanation.slice(0, 240) : "Possible safety concern; review context in the app.";
    const matchedTerm = typeof event.payload.matchedTerm === "string" ? event.payload.matchedTerm.trim().slice(0, 80) : undefined;
    // New clients send only classified metadata. Strip raw screen text and arbitrary payload keys.
    storedPayload = { riskCategory, riskSeverity, ruleIds, packageName, explanation, ...(matchedTerm ? { matchedTerm } : {}), dedupKey: riskDedupKey, retentionClass: "monitoring_event_v1" };
  } else if (event.type === "blocked_content") {
    // Keep the old alert contract while ignoring its optional screen excerpt and unknown fields.
    storedPayload = {
      ...(typeof event.payload.deviceName === "string" ? { deviceName: event.payload.deviceName.slice(0, 120) } : {}),
      ...(typeof event.payload.blockedTerm === "string" ? { blockedTerm: event.payload.blockedTerm.slice(0, 160) } : {}),
      ...(typeof event.payload.packageName === "string" ? { packageName: event.payload.packageName.slice(0, 180) } : {}),
      retentionClass: "monitoring_event_v1",
    };
  }
  await prisma.$transaction([
    prisma.deviceActivityEvent.create({ data: { deviceId: device.id, childId: device.childId, type: event.type, payload: storedPayload as Prisma.InputJsonValue, createdAt } }),
    prisma.device.update({ where: { id: device.id }, data: { status: event.type === "tamper_event" ? "UNKNOWN" : "ONLINE", lastSeen: createdAt, model: z.string().max(120).optional().parse(event.payload.deviceModel) ?? device.model, osVersion: z.string().max(120).optional().parse(event.payload.osVersion) ?? device.osVersion } }),
  ]);
  if (event.type === "blocked_content" || event.type === "tamper_event") {
    const parent = await prisma.user.findUnique({ where: { id: device.ownerId }, select: { isActive: true, aiGuardianSettings: { select: { language: true } } } });
    if (parent?.isActive) {
      const language = parent.aiGuardianSettings?.language === "en" ? "en" : "sw";
      const legacyBlockedTerm = typeof event.payload.blockedTerm === "string" ? event.payload.blockedTerm.slice(0, 160) : "unsafe content";
      const categoryLabels: Record<string, string> = language === "en"
        ? { self_harm: "possible self-harm indicator", threat: "possible threat", bullying: "possible bullying", unsafe_content: "unsafe content" }
        : { self_harm: "kiashiria kinachoweza kuonyesha kujidhuru", threat: "tishio linalowezekana", bullying: "unyanyasaji unaowezekana", unsafe_content: "maudhui yasiyo salama" };
      const severityLabels: Record<string, string> = language === "en"
        ? { low: "low", medium: "medium", high: "high", urgent: "urgent" }
        : { low: "chini", medium: "wastani", high: "juu", urgent: "dharura" };
      const isClassifiedRisk = !!riskCategory && !!riskSeverity;
      const unsafeContent = riskCategory === "unsafe_content" || (!isClassifiedRisk && event.type === "blocked_content");
      const title = event.type === "tamper_event"
        ? language === "en" ? "Child device protection alert" : "Tahadhari ya ulinzi wa kifaa cha mtoto"
        : unsafeContent
          ? language === "en" ? "Unsafe content blocked" : "Maudhui yasiyo salama yamezuiwa"
          : language === "en" ? "Possible child safety concern" : "Tahadhari inayoweza kuhusiana na usalama wa mtoto";
      const protectionStatus = objectData(event.payload.protectionStatus as Prisma.JsonValue);
      const disabledProtections = Object.entries(protectionStatus).filter(([, enabled]) => enabled === false).map(([key]) => key);
      const protectionLabels: Record<string, string> = language === "en"
        ? { accessibility: "Accessibility", accessibilityService: "Accessibility service", usageAccess: "Usage access", deviceAdmin: "Device administrator", overlayPermission: "Display over other apps", batteryOptimization: "Background battery permission" }
        : { accessibility: "Ruhusa ya ufikivu", accessibilityService: "Huduma ya ufikivu", usageAccess: "Ruhusa ya matumizi", deviceAdmin: "Msimamizi wa kifaa", overlayPermission: "Kuonyesha juu ya programu nyingine", batteryOptimization: "Ruhusa ya betri ya uendeshaji wa nyuma", batteryOptimizedIgnored: "Ruhusa ya kutozuiwa na uokoaji wa betri" };
      const localizedDisabled = disabledProtections.map(key => protectionLabels[key] ?? key).join(", ");
      const body = event.type === "tamper_event"
        ? language === "en"
          ? `${device.name}: ${localizedDisabled ? `Protection was turned off: ${localizedDisabled}.` : "Protection status changed. Open KidGuard to review it."}`
          : `${device.name}: ${localizedDisabled ? `Ulinzi umezimwa: ${localizedDisabled}.` : "Hali ya ulinzi imebadilika. Fungua KidGuard uikague."}`
        : isClassifiedRisk
          ? language === "en"
            ? `${device.name}: ${typeof storedPayload === "object" && "matchedTerm" in storedPayload && typeof storedPayload.matchedTerm === "string" ? `blocked “${storedPayload.matchedTerm}” — ` : ""}${categoryLabels[riskCategory!] ?? "safety"} phrase matched (${severityLabels[riskSeverity!] ?? riskSeverity} signal). Review the alert in KidGuard.`
            : `${device.name}: ${typeof storedPayload === "object" && "matchedTerm" in storedPayload && typeof storedPayload.matchedTerm === "string" ? `limezuia “${storedPayload.matchedTerm}” — ` : ""}${categoryLabels[riskCategory!] ?? "ishara ya usalama"} imegunduliwa (kiashiria cha ${severityLabels[riskSeverity!] ?? riskSeverity}). Fungua KidGuard ukague tahadhari.`
          : language === "en"
            ? `${device.name} blocked: ${legacyBlockedTerm}`
            : `${device.name} imezuia: ${legacyBlockedTerm}`;
      const notificationPayload = { source: event.type, deviceId: device.id, childId: device.childId, ...(event.type === "blocked_content" ? { retentionClass: "monitoring_event_v1" } : {}), ...(isClassifiedRisk ? { riskCategory, riskSeverity, ...(typeof storedPayload === "object" && "matchedTerm" in storedPayload && typeof storedPayload.matchedTerm === "string" ? { blockedTerm: storedPayload.matchedTerm } : {}) } : { blockedTerm: legacyBlockedTerm }) };
      const voiceMetadata = classifySafetyVoice(riskCategory, riskSeverity);
      const notification = await prisma.notification.create({ data: { recipientId: device.ownerId, childId: device.childId, title, body, type: event.type === "tamper_event" || (riskCategory && riskCategory !== "unsafe_content") ? "behavior" : "system", relatedEntity: "device_activity", relatedId: device.id, payload: notificationPayload, ...voiceMetadata } });
      await deliver(notification.id, device.ownerId, title, body, { ...notificationPayload, ...voiceMetadata });
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
  const voiceMetadata = classifyNotificationVoice(data.type);
  const notification = await prisma.notification.create({ data: { recipientId: recipient.id, childId: data.childId, title: data.title, body: data.body, type: data.type, relatedEntity: data.relatedEntity, relatedId: data.relatedId, payload: data.payload as Prisma.InputJsonValue, ...voiceMetadata } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "notification.create", entityType: "notification", entityId: notification.id } });
  await deliver(notification.id, recipient.id, data.title, data.body, { ...data.payload, ...voiceMetadata });
  res.status(201).json(toApiNotification(await prisma.notification.findUniqueOrThrow({ where: { id: notification.id } })));
}));

app.post("/api/notifications/child-parents", authenticate, allow(Role.ADMIN, Role.TEACHER), asyncRoute(async (req, res) => {
  const input = z.object({ childId: z.string().min(1), title: z.string().trim().min(1).max(160), body: z.string().trim().min(1).max(4000), type: z.string().default("system"), payload: z.record(z.unknown()).default({}) }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const { childId, title, body, type, payload } = input.data;
  if (!await canAccessChild(req.principal!, childId)) { res.status(403).json({ error: "Child is outside your authorized scope" }); return; }
  const links = await prisma.parentChild.findMany({ where: { childId, parent: { isActive: true } }, select: { parentId: true } });
  const voiceMetadata = classifyNotificationVoice(type);
  const rows = await prisma.notification.createManyAndReturn({ data: links.map(({ parentId }) => ({ recipientId: parentId, childId, title, body, type, payload: payload as Prisma.InputJsonValue, ...voiceMetadata })) });
  await Promise.all(rows.map(row => deliver(row.id, row.recipientId, title, body, { ...payload, ...voiceMetadata })));
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
  const voiceMetadata = classifyNotificationVoice(type);
  const rows = await prisma.notification.createManyAndReturn({ data: recipients.map(({ id }) => ({ recipientId: id, childId, title, body, type, payload: payload as Prisma.InputJsonValue, ...voiceMetadata })) });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "notification.broadcast", entityType: "notification", details: { recipients: rows.length, roles: [...roles], schoolId: schoolId ?? null } } });
  await Promise.all(rows.map(row => deliver(row.id, row.recipientId, title, body, { ...payload, ...voiceMetadata })));
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
  const pendingNotifications = await prisma.notification.findMany({
    where: { recipientId: req.principal!.id, deliveryStatus: { in: ["PENDING", "FAILED"] }, createdAt: { gte: new Date(Date.now() - 24 * 60 * 60_000) } },
    orderBy: { createdAt: "desc" }, take: 25,
  });
  await Promise.all(pendingNotifications.map(row => deliver(row.id, req.principal!.id, row.title, row.body, { ...(row.payload as Record<string, unknown>), ...classifyNotificationVoice(row.type) })));
  res.json({ id: device.id });
}));

app.delete("/api/devices/push-token", authenticate, asyncRoute(async (req, res) => {
  const result = await prisma.device.updateMany({ where: { ownerId: req.principal!.id, childId: null, fcmToken: { not: null } }, data: { fcmToken: null, status: "OFFLINE" } });
  res.json({ unregistered: result.count });
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

app.patch("/api/devices/:deviceId", authenticate, asyncRoute(async (req, res) => {
  const deviceId = req.params.deviceId.toString();
  const input = z.object({ name: z.string().trim().min(1).max(120) }).strict().safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: "Device name must be 1–120 characters" }); return; }
  const device = await prisma.device.findUnique({ where: { id: deviceId }, select: { id: true, ownerId: true, schoolId: true } });
  if (!device) { res.status(404).json({ error: "Device not found" }); return; }
  const permitted = device.ownerId === req.principal!.id ||
    (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || device.schoolId === req.principal!.schoolId));
  if (!permitted) { res.status(403).json({ error: "Only the device owner or an authorized administrator can edit this device" }); return; }
  const updated = await prisma.device.update({ where: { id: deviceId }, data: { name: input.data.name }, select: { id: true, name: true, updatedAt: true } });
  await prisma.auditLog.create({ data: { actorId: req.principal!.id, action: "device.rename", entityType: "device", entityId: deviceId } });
  res.json({ device: updated });
}));

app.patch("/api/devices/:deviceId/status", authenticate, asyncRoute(async (req, res) => {
  const input = z.object({ status: z.enum(["ONLINE", "OFFLINE", "UNKNOWN"]), batteryLevel: z.number().min(0).max(100).optional(), isCharging: z.boolean().optional(), storageUsed: z.number().nonnegative().optional(), storageTotal: z.number().nonnegative().optional(), memoryUsed: z.number().nonnegative().optional(), memoryTotal: z.number().nonnegative().optional() }).safeParse(req.body);
  if (!input.success) { res.status(400).json({ error: input.error.flatten() }); return; }
  const device = await prisma.device.findUnique({ where: { id: req.params.deviceId.toString() } });
  if (!device) { res.status(404).json({ error: "Device not found" }); return; }
  const permitted = device.childId ? await canAccessChild(req.principal!, device.childId) : device.ownerId === req.principal!.id || (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || device.schoolId === req.principal!.schoolId));
  if (!permitted) { res.status(403).json({ error: "Device is outside your authorized scope" }); return; }
  const updated = await prisma.device.update({ where: { id: device.id }, data: { ...input.data, ...(device.childId ? { status: device.status } : { lastSeen: new Date() }) } });
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
  const childDeviceIds = devices.filter(device => device.childId).map(device => device.id);
  const heartbeatCutoff = new Date(Date.now() - 35 * 60 * 1000);
  const recentHeartbeats = childDeviceIds.length ? await prisma.deviceActivityEvent.findMany({
    where: { deviceId: { in: childDeviceIds }, type: "device_heartbeat", createdAt: { gte: heartbeatCutoff } },
    orderBy: { createdAt: "desc" },
    distinct: ["deviceId"], take: childDeviceIds.length,
    select: { deviceId: true, payload: true, createdAt: true },
  }) : [];
  const latestMonitoringHeartbeat = new Map<string, { active: boolean; accessibilityActive: boolean; usageAccessActive: boolean; at: Date }>();
  for (const heartbeat of recentHeartbeats) {
    if (latestMonitoringHeartbeat.has(heartbeat.deviceId)) continue;
    const payload = heartbeat.payload as Record<string, unknown>;
    const accessibilityActive = payload.accessibilityActive === true;
    const usageAccessActive = payload.usageAccessActive === true;
    latestMonitoringHeartbeat.set(heartbeat.deviceId, { active: payload.monitoringActive === true && accessibilityActive && usageAccessActive, accessibilityActive, usageAccessActive, at: heartbeat.createdAt });
  }
  res.json({ devices: devices.map(({ fcmToken: _token, deviceKey: _deviceKey, deviceSecretHash: _secret, ...device }) => {
    const heartbeat = latestMonitoringHeartbeat.get(device.id);
    const recentHeartbeat = !!heartbeat && heartbeat.at >= heartbeatCutoff;
    const connected = !!device.lastSeen && device.lastSeen >= heartbeatCutoff;
    const monitoringState = !device.childId ? null : !recentHeartbeat ? "no_recent_heartbeat" : !heartbeat?.accessibilityActive ? "accessibility_disabled" : !heartbeat?.usageAccessActive ? "usage_access_disabled" : !heartbeat.active ? "service_stopped" : "active";
    return { ...device, ...(device.childId ? { status: connected ? "ONLINE" : "OFFLINE" } : {}), userId: device.childId ?? device.ownerId, deviceName: device.name, type: device.platform.toLowerCase(), deviceModel: device.model, isActive: device.isAuthorized, canDelete: device.ownerId === user.id || (user.role === Role.ADMIN && (!user.schoolId || device.schoolId === user.schoolId)), monitoringActive: device.childId ? recentHeartbeat && heartbeat.active : null, monitoringState, monitoringHeartbeatAt: device.childId && heartbeat ? heartbeat.at.toISOString() : null };
  }) });
}));

app.get("/api/devices/:deviceId", authenticate, asyncRoute(async (req, res) => {
  const device = await prisma.device.findUnique({ where: { id: req.params.deviceId.toString() } });
  if (!device) { res.status(404).json({ error: "Device not found" }); return; }
  const permitted = device.childId ? await canAccessChild(req.principal!, device.childId) : device.ownerId === req.principal!.id || (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || device.schoolId === req.principal!.schoolId));
  if (!permitted) { res.status(403).json({ error: "Device is outside your authorized scope" }); return; }
  const { fcmToken: _token, deviceKey: _key, deviceSecretHash: _secret, ...safe } = device;
  const canDelete = device.ownerId === req.principal!.id || (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || device.schoolId === req.principal!.schoolId));
  const heartbeatCutoff = new Date(Date.now() - 35 * 60 * 1000);
  const connected = !!safe.lastSeen && safe.lastSeen >= heartbeatCutoff;
  const heartbeat = safe.childId ? await prisma.deviceActivityEvent.findFirst({ where: { deviceId: safe.id, type: "device_heartbeat", createdAt: { gte: heartbeatCutoff } }, orderBy: { createdAt: "desc" }, select: { payload: true, createdAt: true } }) : null;
  const heartbeatPayload = heartbeat?.payload as Record<string, unknown> | undefined;
  const accessibilityActive = heartbeatPayload?.accessibilityActive === true;
  const usageAccessActive = heartbeatPayload?.usageAccessActive === true;
  const monitoringActive = !!heartbeat && heartbeatPayload?.monitoringActive === true && accessibilityActive && usageAccessActive;
  const monitoringState = !safe.childId ? null : !heartbeat ? "no_recent_heartbeat" : !accessibilityActive ? "accessibility_disabled" : !usageAccessActive ? "usage_access_disabled" : !monitoringActive ? "service_stopped" : "active";
  res.json({ device: { ...safe, ...(safe.childId ? { status: connected ? "ONLINE" : "OFFLINE" } : {}), userId: safe.childId ?? safe.ownerId, deviceName: safe.name, type: safe.platform.toLowerCase(), deviceModel: safe.model, isActive: safe.isAuthorized, canDelete, ...(safe.childId ? { monitoringActive, monitoringState, monitoringHeartbeatAt: heartbeat?.createdAt.toISOString() ?? null } : {}) } });
}));

app.delete("/api/devices/:deviceId", authenticate, asyncRoute(async (req, res) => {
  const deviceId = req.params.deviceId.toString();
  const device = await prisma.device.findUnique({ where: { id: deviceId }, select: { id: true, ownerId: true, schoolId: true } });
  if (!device) { res.status(404).json({ error: "Device not found" }); return; }
  const permitted = device.ownerId === req.principal!.id || (req.principal!.role === Role.ADMIN && (!req.principal!.schoolId || device.schoolId === req.principal!.schoolId));
  if (!permitted) { res.status(403).json({ error: "Only the device owner or an authorized administrator can remove this device" }); return; }
  await prisma.$transaction(async transaction => {
    await transaction.auditLog.create({ data: { actorId: req.principal!.id, action: "device.delete", entityType: "device", entityId: device.id } });
    await transaction.deviceLinkToken.deleteMany({ where: { deviceId: device.id } });
    await transaction.device.delete({ where: { id: device.id } });
  });
  res.status(204).end();
}));

app.get("/api/children/:childId/activity", authenticate, asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  const take = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
  const events = await prisma.deviceActivityEvent.findMany({ where: { childId }, orderBy: { createdAt: "desc" }, take });
  res.json({ events: events.map(event => ({ id: event.id, type: event.type, childId: event.childId, deviceId: event.deviceId, deviceName: typeof (event.payload as Record<string, unknown>).deviceName === "string" ? (event.payload as Record<string, unknown>).deviceName : "Device", createdAt: event.createdAt.toISOString(), ...(event.payload as Record<string, unknown>) })) });
}));

app.post("/api/children/:childId/locations", authenticate, asyncRoute(async (req, res) => {
  res.status(410).json({ error: "Location reports must come from an authorized paired device" });
}));

app.get("/api/children/:childId/locations", authenticate, asyncRoute(async (req, res) => {
  const childId = req.params.childId.toString();
  if (!await canAccessChild(req.principal!, childId)) { res.status(404).json({ error: "Child not found in your authorized scope" }); return; }
  const from = typeof req.query.from === "string" ? new Date(req.query.from) : new Date(Date.now() - 7 * 86_400_000);
  const to = typeof req.query.to === "string" ? new Date(req.query.to) : new Date();
  if (Number.isNaN(from.valueOf()) || Number.isNaN(to.valueOf())) { res.status(400).json({ error: "Invalid location time range" }); return; }
  const take = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
  const locations = await prisma.deviceLocation.findMany({ where: { childId, timestamp: { gte: from, lte: to }, device: { isAuthorized: true } }, orderBy: { timestamp: "desc" }, take });
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
  const tokens = (await prisma.device.findMany({ where: { ownerId: recipientId, childId: null, fcmToken: { not: null } }, select: { fcmToken: true } })).map(d => d.fcmToken!).filter(Boolean);
  if (!tokens.length || !getApps().length) {
    await prisma.notification.update({ where: { id }, data: { deliveryStatus: "FAILED", deliveryError: !tokens.length ? "no_registered_push_token" : "firebase_admin_not_configured" } });
    return;
  }
  try {
    const voice = await prisma.notification.findUnique({ where: { id }, select: { priority: true, voiceEnabled: true, requiresVoiceAlert: true, voiceCategory: true } });
    const { getMessaging } = await import("firebase-admin/messaging");
    const critical = voice?.priority === "CRITICAL" || voice?.priority === "HIGH";
    const response = await getMessaging().sendEachForMulticast({
      tokens,
      notification: { title, body },
      android: {
        priority: critical ? "high" : "normal",
        ttl: 4 * 7 * 24 * 60 * 60 * 1000,
        notification: { channelId: "kidguard_alerts", priority: critical ? "high" : "default", sound: "default" },
      },
      data: { notificationId: id, ...Object.fromEntries(Object.entries(payload).map(([key, value]) => [key, typeof value === "string" ? value : JSON.stringify(value)])), priority: voice?.priority ?? "NORMAL", voiceEnabled: String(voice?.voiceEnabled ?? false), requiresVoiceAlert: String(voice?.requiresVoiceAlert ?? false), voiceCategory: voice?.voiceCategory ?? "GENERAL" },
    });
    const invalidTokens = response.responses.flatMap((result, index) => {
      const code = result.error?.code;
      return !result.success && (code === "messaging/registration-token-not-registered" || code === "messaging/invalid-registration-token") ? [tokens[index]] : [];
    });
    if (invalidTokens.length) await prisma.device.updateMany({ where: { fcmToken: { in: invalidTokens } }, data: { fcmToken: null } });
    await prisma.notification.update({ where: { id }, data: { deliveryStatus: response.successCount ? "SENT" : "FAILED", deliveryError: response.failureCount ? `${response.failureCount} device(s) failed` : null, deliveredAt: response.successCount ? new Date() : null } });
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error && typeof error.code === "string" ? error.code : "fcm_delivery_failed";
    await prisma.notification.update({ where: { id }, data: { deliveryStatus: "FAILED", deliveryError: code.slice(0, 120) } });
  }
}

function toApiNotification(row: { id: string; recipientId: string; title: string; body: string; type: string; relatedEntity: string | null; relatedId: string | null; payload: Prisma.JsonValue; isRead: boolean; createdAt: Date; readAt: Date | null; deliveryStatus: string; childId: string | null; priority: string; voiceEnabled: boolean; requiresVoiceAlert: boolean; voiceCategory: string }) {
  return { id: row.id, recipientId: row.recipientId, title: row.title, body: row.body, type: row.type, relatedEntity: row.relatedEntity, relatedId: row.relatedId, payload: row.payload, isRead: row.isRead, createdAt: row.createdAt.toISOString(), readAt: row.readAt?.toISOString() ?? null, deliveryStatus: row.deliveryStatus, childId: row.childId, priority: row.priority, voiceEnabled: row.voiceEnabled, requiresVoiceAlert: row.requiresVoiceAlert, voiceCategory: row.voiceCategory };
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
  const devices = await prisma.device.findMany({ where: { ownerId: { not: null }, isAuthorized: true }, select: { id: true, ownerId: true, childId: true, name: true, status: true, lastSeen: true } });
  const byParent = new Map<string, typeof devices>();
  for (const device of devices) {
    if (!device.ownerId) continue;
    const current = byParent.get(device.ownerId) ?? [];
    current.push(device);
    byParent.set(device.ownerId, current);
  }
  for (const [parentId, parentDevices] of byParent) {
    if (await prisma.dailyUsageSummary.findUnique({ where: { parentId_dayKey: { parentId, dayKey } }, select: { id: true } })) continue;
    const language = (await prisma.aIGuardianSettings.findUnique({ where: { userId: parentId }, select: { language: true } }))?.language === "en" ? "en" : "sw";
    const monitoredDevices = parentDevices.filter(device => device.childId !== null);
    const deviceIds = monitoredDevices.map(device => device.id);
    const events = await prisma.deviceActivityEvent.findMany({ where: { deviceId: { in: deviceIds }, type: "app_usage_summary", createdAt: { gte: start, lt: end } }, orderBy: { createdAt: "desc" }, select: { deviceId: true, payload: true } });
    const checkIns = deviceIds.length ? await prisma.deviceActivityEvent.findMany({ where: { deviceId: { in: deviceIds }, type: "device_heartbeat", createdAt: { gte: start, lt: end } }, distinct: ["deviceId"], select: { deviceId: true } }) : [];
    const apps = new Map<string, { appName: string; minutes: number }>();
    let totalMinutes = 0;
    const summarizedDeviceIds = new Set<string>();
    for (const event of events) {
      // Device reports are rolling snapshots; only the latest snapshot per device is authoritative.
      if (summarizedDeviceIds.has(event.deviceId)) continue;
      summarizedDeviceIds.add(event.deviceId);
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
    const duration = language === "en"
      ? hours ? `${hours}h ${minutes}m` : `${minutes}m`
      : hours ? `${hours} saa na dakika ${minutes}` : `dakika ${minutes}`;
    const appsText = topApps.slice(0, 3).map(item => `${item.appName} ${item.minutes}m`).join(", ");
    const active = checkIns.length;
    const inactive = Math.max(0, monitoredDevices.length - active);
    const body = language === "en"
      ? topApps.length
        ? `Recorded device use yesterday: ${duration}. Top apps: ${appsText}. Devices reporting: ${active}; not reporting: ${inactive}.`
        : `No significant device use was recorded yesterday. Devices reporting: ${active}; not reporting: ${inactive}.`
      : topApps.length
        ? `Matumizi ya kifaa yaliyorekodiwa jana: ${duration}. Programu zilizotumika zaidi: ${appsText}. Vifaa vilivyoripoti: ${active}; ambavyo havikuripoti: ${inactive}.`
        : `Hakuna matumizi makubwa ya kifaa yaliyorekodiwa jana. Vifaa vilivyoripoti: ${active}; ambavyo havikuripoti: ${inactive}.`;
    const title = language === "en" ? "Yesterday's device usage summary" : "Muhtasari wa matumizi ya jana";
    try {
      const notification = await prisma.$transaction(async transaction => {
        if (await transaction.dailyUsageSummary.findUnique({ where: { parentId_dayKey: { parentId, dayKey } }, select: { id: true } })) return null;
        await transaction.dailyUsageSummary.create({ data: { parentId, dayKey, totalMinutes: total, topApps: topApps as Prisma.InputJsonValue, childIds: [...new Set(monitoredDevices.flatMap(device => device.childId ? [device.childId] : []))], deviceIds, eventCount: summarizedDeviceIds.size, activeDevices: active, inactiveDevices: inactive } });
        return transaction.notification.create({ data: { recipientId: parentId, title, body, type: "system", relatedEntity: "daily_usage_summary", relatedId: dayKey, payload: { source: "daily_usage_summary", dayKey, totalMinutes: total, activeDevices: active, inactiveDevices: inactive }, ...classifyNotificationVoice("system") } });
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
const monitoringRetentionTimer = setInterval(() => { void pruneExpiredMonitoringData().catch(() => console.error("Monitoring retention job failed")); }, 24 * 60 * 60 * 1000);
const locationRetentionTimer = setInterval(() => { void pruneExpiredLocations().catch(() => console.error("Location retention job failed")); }, 24 * 60 * 60 * 1000);
async function pruneExpiredMonitoringData() {
  const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  // Only records explicitly tagged by the privacy-first event contract are pruned.
  // Older imported/legacy records remain untouched pending a separate retention decision.
  await prisma.deviceActivityEvent.deleteMany({
    where: { createdAt: { lt: cutoff }, payload: { path: ["retentionClass"], equals: "monitoring_event_v1" } },
  });
  await prisma.notification.deleteMany({
    where: { createdAt: { lt: cutoff }, payload: { path: ["retentionClass"], equals: "monitoring_event_v1" } },
  });
}
void pruneExpiredMonitoringData().catch(() => console.error("Monitoring retention job failed"));
void pruneExpiredLocations().catch(() => console.error("Location retention job failed"));
void createDailyUsageSummaries().catch(error => console.error("Daily usage summary job failed", error));
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => server.close(() => { clearInterval(dailySummaryTimer); clearInterval(monitoringRetentionTimer); clearInterval(locationRetentionTimer); void prisma.$disconnect().finally(() => process.exit(0)); }));

async function pruneExpiredLocations() {
  await prisma.deviceLocation.deleteMany({ where: { retentionClass: "child_gps_v1", timestamp: { lt: new Date(Date.now() - 30 * 86_400_000) } } });
}
