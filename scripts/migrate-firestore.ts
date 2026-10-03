import "dotenv/config";
import { cert, initializeApp } from "firebase-admin/app";
import { getFirestore, Timestamp } from "firebase-admin/firestore";
import { DevicePlatform, DeviceStatus, Prisma, PrismaClient, Role } from "@prisma/client";
import { createHash } from "node:crypto";

const dryRun = process.argv.includes("--dry-run");
const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) as { project_id?: string; client_email?: string; private_key?: string }
  : undefined;
const projectId = process.env.FIREBASE_PROJECT_ID || serviceAccount?.project_id;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL || serviceAccount?.client_email;
const privateKey = (process.env.FIREBASE_PRIVATE_KEY || serviceAccount?.private_key)?.replace(/\\n/g, "\n");
if (!projectId || !clientEmail || !privateKey) throw new Error("Set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY before importing.");
if (!process.env.DATABASE_URL) throw new Error("Set DATABASE_URL to the PostgreSQL target before importing.");

const app = initializeApp({ credential: cert({ projectId, clientEmail, privateKey }) }, "kidguard-firestore-import");
const firestore = getFirestore(app);
const prisma = new PrismaClient();
const supported = new Set(["schools", "classes", "users", "devices", "notifications", "child_activity_events", "locations", "screen_time"]);
const idOf = (value: unknown): string | undefined => typeof value === "string" && value.trim() ? value.trim() : undefined;

function dateOf(value: unknown): Date | undefined {
  if (value instanceof Date) return value;
  if (value instanceof Timestamp) return value.toDate();
  if (value && typeof value === "object" && "toDate" in value && typeof value.toDate === "function") return value.toDate();
  if (typeof value === "string" || typeof value === "number") { const parsed = new Date(value); if (!Number.isNaN(parsed.valueOf())) return parsed; }
  return undefined;
}

function jsonSafe(value: unknown): unknown {
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Timestamp) return value.toDate().toISOString();
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined).map(([key, item]) => [key, jsonSafe(item)]));
  return value;
}

function roleOf(value: unknown): Role | "CHILD" | undefined {
  const role = String(value ?? "").toLowerCase().trim();
  if (role === "admin" || role === "administrator") return Role.ADMIN;
  if (role === "teacher" || role === "teachers") return Role.TEACHER;
  if (role === "parent" || role === "parents") return Role.PARENT;
  if (role === "child" || role === "student" || role === "students") return "CHILD";
  return undefined;
}

async function main() {
  const schoolDocs = (await firestore.collection("schools").get()).docs;
  const classDocs = (await firestore.collection("classes").get()).docs;
  const userDocs = (await firestore.collection("users").get()).docs;
  const deviceDocs = (await firestore.collection("devices").get()).docs;
  const notificationDocs = (await firestore.collection("notifications").get()).docs;
  const activityDocs = (await firestore.collection("child_activity_events").get()).docs;
  const locationDocs = (await firestore.collection("locations").get()).docs;
  const screenTimeDocs = (await firestore.collection("screen_time").get()).docs;
  const collections = await firestore.listCollections();
  console.log(`Found ${schoolDocs.length} schools, ${classDocs.length} classes, ${userDocs.length} user/child records, ${deviceDocs.length} devices, ${notificationDocs.length} notifications, ${activityDocs.length} activity events, ${locationDocs.length} locations, ${screenTimeDocs.length} screen-time records, and ${collections.length} top-level collections.`);
  if (dryRun) { console.log("Dry run complete; no PostgreSQL records were written."); return; }

  for (const doc of schoolDocs) {
    const data = doc.data();
    const values = { name: idOf(data.name) ?? "School", code: idOf(data.code), address: idOf(data.address), phone: idOf(data.phone), email: idOf(data.email), website: idOf(data.website), logoUrl: idOf(data.logoUrl), description: idOf(data.description), motto: idOf(data.motto), principalName: idOf(data.principalName), isActive: data.isActive !== false, settings: jsonSafe(data) as Prisma.InputJsonValue, createdAt: dateOf(data.createdAt) ?? new Date(), updatedAt: dateOf(data.updatedAt) ?? new Date() };
    await prisma.school.upsert({ where: { id: doc.id }, create: { id: doc.id, ...values }, update: values });
  }

  for (const doc of classDocs) {
    const data = doc.data();
    const schoolId = idOf(data.schoolId);
    if (!schoolId || !await prisma.school.findUnique({ where: { id: schoolId }, select: { id: true } })) {
      await prisma.legacyRecord.upsert({ where: { collection_sourceId: { collection: "classes_unmapped", sourceId: doc.id } }, create: { collection: "classes_unmapped", sourceId: doc.id, data: jsonSafe(data) as Prisma.InputJsonValue }, update: { data: jsonSafe(data) as Prisma.InputJsonValue } });
      continue;
    }
    const values = { schoolId, name: idOf(data.name) ?? idOf(data.className) ?? "Class", gradeLevel: idOf(data.gradeLevel), academicYear: idOf(data.academicYear), settings: jsonSafe(data) as Prisma.InputJsonValue, createdAt: dateOf(data.createdAt) ?? new Date(), updatedAt: dateOf(data.updatedAt) ?? new Date() };
    await prisma.schoolClass.upsert({ where: { id: doc.id }, create: { id: doc.id, ...values }, update: values });
  }

  const childDocs = userDocs.filter(doc => roleOf(doc.data().role) === "CHILD");
  const accountDocs = userDocs.filter(doc => [Role.ADMIN, Role.TEACHER, Role.PARENT].includes(roleOf(doc.data().role) as Role));
  for (const doc of accountDocs) {
    const data = doc.data();
    const schoolId = idOf(data.schoolId);
    const schoolExists = schoolId ? await prisma.school.findUnique({ where: { id: schoolId }, select: { id: true } }) : null;
    const email = idOf(data.email) ?? `${doc.id}@legacy.kidguard.invalid`;
    const values = { firebaseUid: idOf(data.firebaseUid) ?? doc.id, email, fullName: idOf(data.fullName) ?? idOf(data.name) ?? email, phone: idOf(data.phone), profileImageUrl: idOf(data.profileImageUrl), preferences: jsonSafe(data.preferences ?? {}) as Prisma.InputJsonValue, isPremium: data.isPremium === true, premiumExpiry: dateOf(data.premiumExpiry), role: roleOf(data.role) as Role, schoolId: schoolExists?.id, createdAt: dateOf(data.createdAt) ?? new Date(), updatedAt: dateOf(data.updatedAt) ?? new Date() };
    await prisma.user.upsert({ where: { firebaseUid: values.firebaseUid }, create: { id: doc.id, ...values }, update: values });
    const preferences = data.notificationPreferences ?? data.preferences;
    if (preferences && typeof preferences === "object") await prisma.notificationPreference.upsert({ where: { userId: doc.id }, create: { userId: doc.id, types: jsonSafe(preferences) as Prisma.InputJsonValue }, update: { types: jsonSafe(preferences) as Prisma.InputJsonValue } });
  }

  for (const doc of childDocs) {
    const data = doc.data();
    const schoolId = idOf(data.schoolId);
    const exists = schoolId ? await prisma.school.findUnique({ where: { id: schoolId }, select: { id: true } }) : null;
    let classId = idOf(data.classId);
    if (classId && !await prisma.schoolClass.findUnique({ where: { id: classId }, select: { id: true } })) classId = undefined;
    if (!classId && exists?.id && idOf(data.className)) classId = (await prisma.schoolClass.findFirst({ where: { schoolId: exists.id, name: data.className }, select: { id: true } }))?.id;
    await prisma.child.upsert({ where: { id: doc.id }, create: { id: doc.id, fullName: idOf(data.fullName) ?? idOf(data.name) ?? "Student", linkCode: idOf(data.linkCode) ?? idOf(data.childCode) ?? idOf(data.phone), schoolId: exists?.id, classId, className: idOf(data.className), createdAt: dateOf(data.createdAt) ?? new Date(), updatedAt: dateOf(data.updatedAt) ?? new Date() }, update: { fullName: idOf(data.fullName) ?? idOf(data.name) ?? "Student", linkCode: idOf(data.linkCode) ?? idOf(data.childCode) ?? idOf(data.phone), schoolId: exists?.id, classId, className: idOf(data.className), updatedAt: dateOf(data.updatedAt) ?? new Date() } });
  }

  for (const doc of userDocs.filter(user => !roleOf(user.data().role))) {
    await prisma.legacyRecord.upsert({ where: { collection_sourceId: { collection: "users_unmapped", sourceId: doc.id } }, create: { collection: "users_unmapped", sourceId: doc.id, data: jsonSafe(doc.data()) as Prisma.InputJsonValue }, update: { data: jsonSafe(doc.data()) as Prisma.InputJsonValue } });
  }

  for (const doc of accountDocs) {
    const data = doc.data();
    const account = await prisma.user.findUnique({ where: { firebaseUid: idOf(data.firebaseUid) ?? doc.id }, select: { id: true } });
    if (!account) continue;
    const links = new Set<string>([
      ...(Array.isArray(data.childrenIds) ? data.childrenIds.filter((v: unknown): v is string => typeof v === "string") : []),
      ...childDocs.filter(child => Array.isArray(child.data().parentIds) && child.data().parentIds.includes(doc.id)).map(child => child.id),
    ]);
    if (roleOf(data.role) === Role.PARENT) {
      for (const childId of links) if (await prisma.child.findUnique({ where: { id: childId }, select: { id: true } })) await prisma.parentChild.upsert({ where: { parentId_childId: { parentId: account.id, childId } }, create: { parentId: account.id, childId }, update: {} });
    }
    const studentIds = new Set<string>(Array.isArray(data.studentIds) ? data.studentIds.filter((v: unknown): v is string => typeof v === "string") : []);
    if (roleOf(data.role) === Role.TEACHER) for (const child of childDocs) if (Array.isArray(child.data().teacherIds) && child.data().teacherIds.includes(doc.id)) studentIds.add(child.id);
    if (roleOf(data.role) === Role.TEACHER) for (const childId of studentIds) if (await prisma.child.findUnique({ where: { id: childId }, select: { id: true } })) await prisma.teacherStudent.upsert({ where: { teacherId_studentId: { teacherId: account.id, studentId: childId } }, create: { teacherId: account.id, studentId: childId }, update: {} });
  }

  for (const doc of deviceDocs) {
    const data = doc.data();
    const token = idOf(data.fcmToken);
    const parentId = idOf(data.parentId) ?? idOf(data.userId);
    const parent = parentId ? await prisma.user.findFirst({ where: { OR: [{ id: parentId }, { firebaseUid: parentId }] }, select: { id: true, schoolId: true } }) : null;
    const childId = idOf(data.childId) ?? idOf(data.studentId);
    const child = childId ? await prisma.child.findUnique({ where: { id: childId }, select: { id: true, schoolId: true } }) : null;
    const platform = String(data.platform ?? data.type ?? "ANDROID").toUpperCase();
    const validPlatform = Object.values(DevicePlatform).includes(platform as DevicePlatform) ? platform as DevicePlatform : DevicePlatform.ANDROID;
    const status = String(data.status ?? "UNKNOWN").toUpperCase();
    const validStatus = Object.values(DeviceStatus).includes(status as DeviceStatus) ? status as DeviceStatus : DeviceStatus.UNKNOWN;
    const existingTokenDevice = token ? await prisma.device.findUnique({ where: { fcmToken: token }, select: { deviceKey: true } }) : null;
    const deviceKey = existingTokenDevice?.deviceKey ?? `legacy:${doc.id}`;
    const value = { childId: child?.id, schoolId: child?.schoolId ?? parent?.schoolId, ownerId: parent?.id, platform: validPlatform, name: idOf(data.deviceName) ?? idOf(data.name) ?? "Registered device", model: idOf(data.model), osVersion: idOf(data.osVersion), appVersion: idOf(data.appVersion), batteryLevel: typeof data.batteryLevel === "number" ? data.batteryLevel : undefined, isCharging: data.isCharging === true, storageUsed: typeof data.storageUsed === "number" ? data.storageUsed : undefined, storageTotal: typeof data.storageTotal === "number" ? data.storageTotal : undefined, memoryUsed: typeof data.memoryUsed === "number" ? data.memoryUsed : undefined, memoryTotal: typeof data.memoryTotal === "number" ? data.memoryTotal : undefined, fcmToken: token, deviceSecretHash: idOf(data.deviceSecret) ? createHash("sha256").update(idOf(data.deviceSecret)!).digest("hex") : undefined, status: validStatus, lastSeen: dateOf(data.lastSeen), isAuthorized: data.isAuthorized === true || data.isActive === true, createdAt: dateOf(data.createdAt) ?? new Date(), updatedAt: dateOf(data.updatedAt) ?? new Date() };
    const importedDevice = await prisma.device.upsert({ where: { deviceKey }, create: { deviceKey, ...value }, update: value });
    if (parent) await prisma.deviceRegistration.upsert({ where: { deviceId_actorId: { deviceId: importedDevice.id, actorId: parent.id } }, create: { deviceId: importedDevice.id, actorId: parent.id, authorized: value.isAuthorized, createdAt: dateOf(data.registeredAt) ?? value.createdAt }, update: { authorized: value.isAuthorized } });
  }

  for (const doc of activityDocs) {
    const data = doc.data();
    const childId = idOf(data.childId);
    const oldDeviceId = idOf(data.deviceId);
    const device = oldDeviceId ? await prisma.device.findUnique({ where: { deviceKey: `legacy:${oldDeviceId}` }, select: { id: true, childId: true } }) : null;
    if (!childId || !device?.id || device.childId !== childId || !await prisma.child.findUnique({ where: { id: childId }, select: { id: true } })) {
      const { deviceSecret: _secret, ...safeData } = data;
      await prisma.legacyRecord.upsert({ where: { collection_sourceId: { collection: "child_activity_events_unmapped", sourceId: doc.id } }, create: { collection: "child_activity_events_unmapped", sourceId: doc.id, data: jsonSafe(safeData) as Prisma.InputJsonValue }, update: { data: jsonSafe(safeData) as Prisma.InputJsonValue } });
      continue;
    }
    const reserved = new Set(["type", "childId", "parentId", "deviceId", "deviceSecret", "createdAt"]);
    const payload = Object.fromEntries(Object.entries(data).filter(([key]) => !reserved.has(key)));
    await prisma.deviceActivityEvent.upsert({ where: { id: doc.id }, create: { id: doc.id, deviceId: device.id, childId, type: idOf(data.type) ?? "legacy_event", payload: jsonSafe(payload) as Prisma.InputJsonValue, createdAt: dateOf(data.createdAt) ?? new Date() }, update: { deviceId: device.id, childId, type: idOf(data.type) ?? "legacy_event", payload: jsonSafe(payload) as Prisma.InputJsonValue, createdAt: dateOf(data.createdAt) ?? new Date() } });
  }

  for (const doc of locationDocs) {
    const data = doc.data();
    const childId = idOf(data.childId) ?? idOf(data.userId);
    const oldDeviceId = idOf(data.deviceId);
    const device = oldDeviceId ? await prisma.device.findUnique({ where: { deviceKey: `legacy:${oldDeviceId}` }, select: { id: true, childId: true } }) : null;
    const child = childId ? await prisma.child.findUnique({ where: { id: childId }, select: { id: true } }) : null;
    if (!child || !device?.id || device.childId !== child.id || typeof data.latitude !== "number" || typeof data.longitude !== "number") {
      await prisma.legacyRecord.upsert({ where: { collection_sourceId: { collection: "locations_unmapped", sourceId: doc.id } }, create: { collection: "locations_unmapped", sourceId: doc.id, data: jsonSafe(data) as Prisma.InputJsonValue }, update: { data: jsonSafe(data) as Prisma.InputJsonValue } });
      continue;
    }
    await prisma.deviceLocation.upsert({ where: { id: doc.id }, create: { id: doc.id, deviceId: device.id, childId: child.id, latitude: data.latitude, longitude: data.longitude, altitude: typeof data.altitude === "number" ? data.altitude : undefined, accuracy: typeof data.accuracy === "number" ? data.accuracy : undefined, speed: typeof data.speed === "number" ? data.speed : undefined, bearing: typeof data.bearing === "number" ? data.bearing : undefined, address: idOf(data.address), placeName: idOf(data.placeName), timestamp: dateOf(data.timestamp) ?? new Date(), createdAt: dateOf(data.createdAt) ?? new Date() }, update: {} });
  }

  for (const doc of screenTimeDocs) {
    const data = doc.data();
    const childId = idOf(data.childId) ?? idOf(data.userId);
    const oldDeviceId = idOf(data.deviceId);
    const device = oldDeviceId ? await prisma.device.findUnique({ where: { deviceKey: `legacy:${oldDeviceId}` }, select: { id: true, childId: true } }) : null;
    const child = childId ? await prisma.child.findUnique({ where: { id: childId }, select: { id: true } }) : null;
    const fallbackDevice = child && !device ? await prisma.device.findFirst({ where: { childId: child.id, isAuthorized: true }, select: { id: true } }) : null;
    const recordDevice = device?.childId === child?.id ? device : fallbackDevice;
    if (!child || !recordDevice || !dateOf(data.date)) {
      await prisma.legacyRecord.upsert({ where: { collection_sourceId: { collection: "screen_time_unmapped", sourceId: doc.id } }, create: { collection: "screen_time_unmapped", sourceId: doc.id, data: jsonSafe(data) as Prisma.InputJsonValue }, update: { data: jsonSafe(data) as Prisma.InputJsonValue } });
      continue;
    }
    const dateParts = new Intl.DateTimeFormat("en-US", { timeZone: "Africa/Nairobi", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(dateOf(data.date)!);
    const dateFields = Object.fromEntries(dateParts.map(part => [part.type, part.value]));
    const date = new Date(Date.UTC(Number(dateFields.year), Number(dateFields.month) - 1, Number(dateFields.day)) - 3 * 3_600_000);
    await prisma.screenTimeRecord.upsert({ where: { deviceId_date: { deviceId: recordDevice.id, date } }, create: { id: doc.id, deviceId: recordDevice.id, childId: child.id, date, totalMinutes: typeof data.totalMinutes === "number" ? data.totalMinutes : 0, unlockedCount: typeof data.unlockedCount === "number" ? data.unlockedCount : 0, appUsage: jsonSafe(data.appUsage ?? {}) as Prisma.InputJsonValue, createdAt: dateOf(data.createdAt) ?? new Date(), updatedAt: dateOf(data.updatedAt) ?? new Date() }, update: {} });
  }

  for (const doc of userDocs) {
    const data = doc.data();
    const parent = await prisma.user.findUnique({ where: { firebaseUid: doc.id }, select: { id: true, schoolId: true } });
    for (const token of Array.isArray(data.fcmTokens) ? data.fcmTokens : []) {
      if (typeof token !== "string" || !token) continue;
      const existingTokenDevice = await prisma.device.findUnique({ where: { fcmToken: token }, select: { deviceKey: true } });
      const key = existingTokenDevice?.deviceKey ?? `legacy-fcm:${createHash("sha256").update(`${doc.id}:${token}`).digest("hex")}`;
      await prisma.device.upsert({ where: { deviceKey: key }, create: { deviceKey: key, ownerId: parent?.id, schoolId: parent?.schoolId, platform: DevicePlatform.ANDROID, name: "Legacy push registration", fcmToken: token, status: DeviceStatus.UNKNOWN }, update: { ownerId: parent?.id, fcmToken: token } });
    }
  }

  for (const doc of notificationDocs) {
    const data = doc.data();
    const recipientUid = idOf(data.userId) ?? idOf(data.recipientUid);
    const recipient = recipientUid ? await prisma.user.findUnique({ where: { firebaseUid: recipientUid }, select: { id: true } }) : null;
    if (!recipient) {
      await prisma.legacyRecord.upsert({ where: { collection_sourceId: { collection: "notifications_unmapped", sourceId: doc.id } }, create: { collection: "notifications_unmapped", sourceId: doc.id, data: jsonSafe(data) as Prisma.InputJsonValue }, update: { data: jsonSafe(data) as Prisma.InputJsonValue } });
      continue;
    }
    const readAt = dateOf(data.readAt);
    const createdAt = dateOf(data.createdAt) ?? new Date();
    await prisma.notification.upsert({ where: { id: doc.id }, create: { id: doc.id, recipientId: recipient.id, title: idOf(data.title) ?? "Notification", body: idOf(data.body) ?? "", type: idOf(data.type) ?? "system", payload: jsonSafe(data.data ?? data.payload ?? {}) as Prisma.InputJsonValue, isRead: data.isRead === true, createdAt, readAt }, update: { recipientId: recipient.id, title: idOf(data.title) ?? "Notification", body: idOf(data.body) ?? "", type: idOf(data.type) ?? "system", payload: jsonSafe(data.data ?? data.payload ?? {}) as Prisma.InputJsonValue, isRead: data.isRead === true, readAt } });
  }

  for (const collection of collections) {
    if (supported.has(collection.id)) continue;
    const documents = (await collection.get()).docs;
    for (const doc of documents) {
      await prisma.legacyRecord.upsert({ where: { collection_sourceId: { collection: collection.id, sourceId: doc.id } }, create: { collection: collection.id, sourceId: doc.id, data: jsonSafe(doc.data()) as Prisma.InputJsonValue }, update: { data: jsonSafe(doc.data()) as Prisma.InputJsonValue } });
    }
    console.log(`Preserved ${documents.length} records from ${collection.id}.`);
  }
  console.log("Firestore import complete. Review counts and relationship mappings before retiring Firestore producers.");
}

main().catch(error => { console.error("Firestore import failed", error); process.exitCode = 1; }).finally(async () => { await prisma.$disconnect(); });
