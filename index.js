const express = require("express");
const admin = require("firebase-admin");

const port = process.env.PORT || 10000;
const lookbackMinutes = Number(process.env.LISTENER_LOOKBACK_MINUTES || 120);
const startedAt = new Date(Date.now() - lookbackMinutes * 60 * 1000);
const dailySummaryHour = Number(process.env.DAILY_SUMMARY_HOUR || 18);
const dailySummaryCheckMinutes = Number(process.env.DAILY_SUMMARY_CHECK_MINUTES || 15);
const dailySummaryTimezoneOffsetMinutes = Number(process.env.DAILY_SUMMARY_TZ_OFFSET_MINUTES || 180);

initializeFirebase();

const db = admin.firestore();
const messaging = admin.messaging();
const app = express();

let notificationUnsubscribe = null;
let activityUnsubscribe = null;
let notificationEventsSeen = 0;
let activityEventsSeen = 0;
let lastNotificationAt = null;
let lastActivityAt = null;
let dailySummaryRuns = 0;
let lastDailySummaryAt = null;
let dailySummaryTimer = null;

app.get("/", (_, response) => {
  response.json({
    ok: true,
    service: "watoto-guard-notification-worker",
    startedAt: startedAt.toISOString(),
    notificationEventsSeen,
    activityEventsSeen,
    lastNotificationAt,
    lastActivityAt,
    dailySummaryRuns,
    lastDailySummaryAt,
  });
});

app.get("/health", (_, response) => {
  response.json({ ok: true });
});

app.listen(port, () => {
  console.log(`WatotoGuard notification worker listening on ${port}`);
  startListeners();
  startDailySummaryScheduler();
});

function initializeFirebase() {
  if (admin.apps.length > 0) return;

  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccountJson) {
    admin.initializeApp({
      credential: admin.credential.cert(JSON.parse(serviceAccountJson)),
      projectId: process.env.FIREBASE_PROJECT_ID || "watotoguard",
    });
    return;
  }

  admin.initializeApp({
    projectId: process.env.FIREBASE_PROJECT_ID || "watotoguard",
  });
}

function startListeners() {
  const cutoff = admin.firestore.Timestamp.fromDate(startedAt);

  notificationUnsubscribe = db
    .collection("notifications")
    .where("createdAt", ">=", cutoff)
    .onSnapshot(
      (snapshot) => {
        snapshot.docChanges().forEach((change) => {
          if (change.type !== "added" && change.type !== "modified") return;
          processNotificationDoc(change.doc).catch((error) => {
            console.error("Failed to process notification", change.doc.id, error);
          });
        });
      },
      (error) => console.error("Notification listener error", error),
    );

  activityUnsubscribe = db
    .collection("child_activity_events")
    .where("createdAt", ">=", cutoff)
    .onSnapshot(
      (snapshot) => {
        snapshot.docChanges().forEach((change) => {
          if (change.type !== "added" && change.type !== "modified") return;
          processActivityDoc(change.doc).catch((error) => {
            console.error("Failed to process activity", change.doc.id, error);
          });
        });
      },
      (error) => console.error("Activity listener error", error),
    );
}

async function processNotificationDoc(snapshot) {
  const notification = snapshot.data() || {};
  if (["sent", "partial", "no_tokens", "skipped"].includes(notification.pushStatus)) {
    return;
  }
  if (notification.pushStatus === "processing" && !isStaleProcessing(notification.pushCheckedAt)) {
    return;
  }

  await snapshot.ref.set(
    {
      pushStatus: "processing",
      pushCheckedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true },
  );

  const userId = notification.userId;
  if (!userId || typeof userId !== "string") {
    await snapshot.ref.set(
      {
        pushStatus: "skipped",
        pushError: "Missing userId",
        pushCheckedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    return;
  }

  const userSnapshot = await db.collection("users").doc(userId).get();
  const user = userSnapshot.data() || {};
  const tokens = Array.isArray(user.fcmTokens)
    ? [...new Set(user.fcmTokens.filter((token) => typeof token === "string" && token))]
    : [];

  if (tokens.length === 0) {
    await snapshot.ref.set(
      {
        pushStatus: "no_tokens",
        pushCheckedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    return;
  }

  const payloadData = buildDataPayload(snapshot.id, notification);
  const response = await messaging.sendEachForMulticast({
    tokens,
    notification: {
      title: stringOrDefault(notification.title, "WatotoGuard"),
      body: stringOrDefault(notification.body, "Una taarifa mpya."),
    },
    data: payloadData,
    android: {
      priority: "high",
      notification: {
        channelId: "watoto_guard_alerts",
        sound: "default",
      },
    },
    apns: {
      payload: {
        aps: {
          sound: "default",
          badge: 1,
        },
      },
    },
  });

  const invalidTokens = [];
  response.responses.forEach((item, index) => {
    if (item.success) return;
    const code = item.error && item.error.code;
    if (
      code === "messaging/registration-token-not-registered" ||
      code === "messaging/invalid-registration-token" ||
      code === "messaging/invalid-argument"
    ) {
      invalidTokens.push(tokens[index]);
    }
  });

  if (invalidTokens.length > 0) {
    await userSnapshot.ref.set(
      {
        fcmTokens: admin.firestore.FieldValue.arrayRemove(...invalidTokens),
        lastFcmTokenCleanupAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
  }

  await snapshot.ref.set(
    {
      pushStatus: response.failureCount === 0 ? "sent" : "partial",
      pushSuccessCount: response.successCount,
      pushFailureCount: response.failureCount,
      pushSentAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true },
  );

  notificationEventsSeen += 1;
  lastNotificationAt = new Date().toISOString();
  console.log("Notification push processed", {
    notificationId: snapshot.id,
    userId,
    successCount: response.successCount,
    failureCount: response.failureCount,
    invalidTokenCount: invalidTokens.length,
  });
}

async function processActivityDoc(snapshot) {
  const activity = snapshot.data() || {};
  if (
    activity.notificationFanoutStatus === "created" ||
    activity.notificationFanoutStatus === "no_recipients" ||
    activity.notificationFanoutStatus === "skipped"
  ) {
    return;
  }
  if (
    activity.notificationFanoutStatus === "processing" &&
    !isStaleProcessing(activity.notificationFanoutAt)
  ) {
    return;
  }

  await snapshot.ref.set(
    {
      notificationFanoutStatus: "processing",
      notificationFanoutAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true },
  );

  const childId = activity.childId;
  const parentId = activity.parentId;
  const type = stringOrDefault(activity.type, "system");
  const deviceName = stringOrDefault(activity.deviceName, "Device ya Mtoto");

  if (!childId || typeof childId !== "string") {
    await snapshot.ref.set(
      {
        notificationFanoutStatus: "skipped",
        notificationFanoutError: "Missing childId",
      },
      { merge: true },
    );
    return;
  }

  if (type === "device_heartbeat") {
    const deviceId = stringOrDefault(activity.deviceId, "");
    const deviceSecret = stringOrDefault(activity.deviceSecret, "");
    if (!deviceId || !deviceSecret) {
      await snapshot.ref.set(
        {
          notificationFanoutStatus: "skipped",
          notificationFanoutError: "Missing heartbeat device credentials",
        },
        { merge: true },
      );
      return;
    }

    const deviceRef = db.collection("devices").doc(deviceId);
    const deviceSnapshot = await deviceRef.get();
    const device = deviceSnapshot.data() || {};
    const validHeartbeat = deviceSnapshot.exists &&
      device.deviceSecret === deviceSecret &&
      device.childId === childId &&
      device.parentId === parentId;

    if (!validHeartbeat) {
      await snapshot.ref.set(
        {
          notificationFanoutStatus: "skipped",
          notificationFanoutError: "Invalid heartbeat credentials",
        },
        { merge: true },
      );
      return;
    }

    await deviceRef.set(
      {
        status: "online",
        lastSeen: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        deviceName: deviceName,
        deviceModel: stringOrDefault(activity.deviceModel, ""),
        osVersion: stringOrDefault(activity.osVersion, ""),
        appVersion: stringOrDefault(activity.appVersion, ""),
        heartbeatSource: "child_activity_event",
      },
      { merge: true },
    );

    await snapshot.ref.set(
      {
        notificationFanoutStatus: "skipped",
        notificationFanoutReason: "device_heartbeat",
        heartbeatProcessedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    return;
  }

  const recipients = new Map();
  const baseData = {
    source: type === "tamper_event" ? "tamper_event" : type === "blocked_content" ? "blocked_content" : "app_usage",
    activityId: snapshot.id,
    childId,
    deviceId: stringOrDefault(activity.deviceId, ""),
  };

  if (type === "tamper_event") {
    const deviceId = stringOrDefault(activity.deviceId, "");
    const deviceSecret = stringOrDefault(activity.deviceSecret, "");
    const validDevice = await validateActivityDevice(deviceId, deviceSecret, childId, parentId);
    if (!validDevice) {
      await snapshot.ref.set(
        {
          notificationFanoutStatus: "skipped",
          notificationFanoutError: "Invalid tamper credentials",
        },
        { merge: true },
      );
      return;
    }

    await db.collection("devices").doc(deviceId).set(
      {
        status: "at_risk",
        riskStatus: "tamper_detected",
        lastTamperAt: admin.firestore.FieldValue.serverTimestamp(),
        lastTamperType: stringOrDefault(activity.tamperType, "tamper_event"),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    recipients.set(parentId, {
      role: "parent",
      title: "Tahadhari: protection imebadilishwa",
      body: `${deviceName}: ${stringOrDefault(activity.message, "Protection settings zimebadilishwa.")}`,
    });
  }
  if (type === "app_usage_summary") {
    await snapshot.ref.set(
      {
        notificationFanoutStatus: "skipped",
        notificationFanoutReason: "daily_summary_pending",
      },
      { merge: true },
    );
    return;
  }

  if (recipients.size === 0) {
    await snapshot.ref.set(
      {
        notificationFanoutStatus: "no_recipients",
        notificationFanoutCount: 0,
      },
      { merge: true },
    );
    return;
  }

  const batch = db.batch();
  recipients.forEach((recipient, userId) => {
    const notificationRef = db.collection("notifications").doc();
    batch.set(notificationRef, {
      title: recipient.title,
      body: recipient.body,
      userId,
      recipientRole: recipient.role,
      audienceRole: recipient.role,
      type: "system",
      isRead: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      data: {
        ...baseData,
        blockedTerm: stringOrDefault(activity.blockedTerm, ""),
      },
    });
  });

  await batch.commit();
  await snapshot.ref.set(
    {
      notificationFanoutStatus: "created",
      notificationFanoutCount: recipients.size,
      notificationFanoutAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true },
  );

  activityEventsSeen += 1;
  lastActivityAt = new Date().toISOString();
  console.log("Activity notifications created", {
    activityId: snapshot.id,
    childId,
    count: recipients.size,
  });
}

async function validateActivityDevice(deviceId, deviceSecret, childId, parentId) {
  if (!deviceId || !deviceSecret || !childId || !parentId) return false;
  const deviceSnapshot = await db.collection("devices").doc(deviceId).get();
  if (!deviceSnapshot.exists) return false;
  const device = deviceSnapshot.data() || {};
  return device.deviceSecret === deviceSecret &&
    device.childId === childId &&
    device.parentId === parentId;
}
function startDailySummaryScheduler() {
  const intervalMs = Math.max(1, dailySummaryCheckMinutes) * 60 * 1000;
  dailySummaryTimer = setInterval(() => {
    runDailyUsageSummaries().catch((error) => {
      console.error("Daily usage summary failed", error);
    });
  }, intervalMs);

  runDailyUsageSummaries().catch((error) => {
    console.error("Initial daily usage summary check failed", error);
  });
}

async function runDailyUsageSummaries(now = new Date()) {
  const localNow = toSummaryLocalTime(now);
  if (localNow.getUTCHours() < dailySummaryHour) return;

  const dayKey = formatSummaryDayKey(localNow);
  const localStart = new Date(Date.UTC(
    localNow.getUTCFullYear(),
    localNow.getUTCMonth(),
    localNow.getUTCDate(),
  ));
  const start = fromSummaryLocalTime(localStart);
  const end = fromSummaryLocalTime(new Date(localStart.getTime() + 24 * 60 * 60 * 1000));

  const eventsSnapshot = await db
    .collection("child_activity_events")
    .where("createdAt", ">=", admin.firestore.Timestamp.fromDate(start))
    .where("createdAt", "<", admin.firestore.Timestamp.fromDate(end))
    .get();

  const summariesByParent = new Map();
  eventsSnapshot.docs.forEach((doc) => {
    const event = doc.data() || {};
    if (event.type !== "app_usage_summary") return;
    const parentId = stringOrDefault(event.parentId, "");
    if (!parentId) return;
    const summary = summariesByParent.get(parentId) || {
      parentId,
      childIds: new Set(),
      deviceIds: new Set(),
      totalMinutes: 0,
      apps: new Map(),
      eventCount: 0,
    };
    summary.eventCount += 1;
    const childId = stringOrDefault(event.childId, "");
    const deviceId = stringOrDefault(event.deviceId, "");
    if (childId) summary.childIds.add(childId);
    if (deviceId) summary.deviceIds.add(deviceId);

    const apps = Array.isArray(event.apps) ? event.apps : [];
    apps.forEach((item) => {
      const appName = stringOrDefault(item.appName, stringOrDefault(item.packageName, "App"));
      const packageName = stringOrDefault(item.packageName, appName);
      const minutes = Math.max(0, Number(item.minutesUsed || 0));
      if (minutes <= 0) return;
      summary.totalMinutes += minutes;
      const appKey = packageName || appName;
      const existing = summary.apps.get(appKey) || { appName, packageName, minutes: 0 };
      existing.minutes += minutes;
      summary.apps.set(appKey, existing);
    });
    summariesByParent.set(parentId, summary);
  });

  const devicesSnapshot = await db
    .collection("devices")
    .where("isActive", "==", true)
    .get();
  devicesSnapshot.docs.forEach((doc) => {
    const device = doc.data() || {};
    const parentId = stringOrDefault(device.parentId, "");
    if (!parentId || summariesByParent.has(parentId)) return;
    summariesByParent.set(parentId, {
      parentId,
      childIds: new Set(),
      deviceIds: new Set([doc.id]),
      totalMinutes: 0,
      apps: new Map(),
      eventCount: 0,
    });
  });

  for (const summary of summariesByParent.values()) {
    await createDailyUsageSummaryNotification(summary, dayKey);
  }

  dailySummaryRuns += 1;
  lastDailySummaryAt = new Date().toISOString();
}

async function createDailyUsageSummaryNotification(summary, dayKey) {
  const summaryRef = db.collection("daily_usage_summaries").doc(`${summary.parentId}_${dayKey}`);
  const existing = await summaryRef.get();
  if (existing.exists) return;

  const deviceCounts = await getParentDeviceCounts(summary.parentId);
  const topApps = [...summary.apps.values()]
    .sort((a, b) => b.minutes - a.minutes)
    .slice(0, 5);

  const totalMinutes = Math.round(summary.totalMinutes);
  const body = buildDailyUsageBody(totalMinutes, topApps, deviceCounts);
  const batch = db.batch();
  batch.set(summaryRef, {
    parentId: summary.parentId,
    dayKey,
    totalMinutes,
    topApps,
    childIds: [...summary.childIds],
    deviceIds: [...summary.deviceIds],
    eventCount: summary.eventCount,
    activeDevices: deviceCounts.active,
    inactiveDevices: deviceCounts.inactive,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  batch.set(db.collection("notifications").doc(), {
    title: "Muhtasari wa matumizi ya leo",
    body,
    userId: summary.parentId,
    recipientRole: "parent",
    audienceRole: "parent",
    type: "system",
    isRead: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    data: {
      source: "daily_usage_summary",
      dayKey,
      totalMinutes: String(totalMinutes),
      activeDevices: String(deviceCounts.active),
      inactiveDevices: String(deviceCounts.inactive),
    },
  });
  await batch.commit();
}

async function getParentDeviceCounts(parentId) {
  const snapshot = await db
    .collection("devices")
    .where("parentId", "==", parentId)
    .where("isActive", "==", true)
    .get();
  let active = 0;
  let inactive = 0;
  snapshot.docs.forEach((doc) => {
    const status = stringOrDefault((doc.data() || {}).status, "offline");
    if (status === "online") active += 1;
    else inactive += 1;
  });
  return { active, inactive };
}

function buildDailyUsageBody(totalMinutes, topApps, deviceCounts) {
  if (totalMinutes <= 0 || topApps.length === 0) {
    return `Leo hakuna matumizi makubwa yaliyorekodiwa. Active: ${deviceCounts.active}, inactive: ${deviceCounts.inactive}.`;
  }
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  const duration = hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
  const apps = topApps
    .slice(0, 3)
    .map((app) => `${app.appName} ${Math.round(app.minutes)}m`)
    .join(", ");
  return `Matumizi ya leo: ${duration}. Apps kuu: ${apps}. Active: ${deviceCounts.active}, inactive: ${deviceCounts.inactive}.`;
}

function toSummaryLocalTime(date) {
  return new Date(date.getTime() + dailySummaryTimezoneOffsetMinutes * 60 * 1000);
}

function fromSummaryLocalTime(date) {
  return new Date(date.getTime() - dailySummaryTimezoneOffsetMinutes * 60 * 1000);
}

function formatSummaryDayKey(localDate) {
  const year = localDate.getUTCFullYear();
  const month = String(localDate.getUTCMonth() + 1).padStart(2, "0");
  const day = String(localDate.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}
function buildDataPayload(notificationId, notification) {
  const data = {
    notificationId,
    type: stringOrDefault(notification.type, "system"),
  };
  const sourceData = notification.data || {};
  if (sourceData && typeof sourceData === "object" && !Array.isArray(sourceData)) {
    for (const [key, value] of Object.entries(sourceData)) {
      if (value === undefined || value === null) continue;
      data[key] = typeof value === "string" ? value : JSON.stringify(value);
    }
  }
  if (!data.source) {
    data.source = data.type;
  }
  return data;
}

function stringOrDefault(value, fallback) {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  return trimmed.length === 0 ? fallback : trimmed;
}

function buildAppUsageBody(deviceName, apps) {
  if (!Array.isArray(apps) || apps.length === 0) {
    return `${deviceName} sent a new activity summary.`;
  }
  const topApps = apps
    .slice(0, 3)
    .map((app) => {
      const appName = stringOrDefault(app.appName, stringOrDefault(app.packageName, "App"));
      const minutes = Number(app.minutesUsed || 0);
      return minutes > 0 ? `${appName} ${minutes}m` : appName;
    })
    .join(", ");
  return `${deviceName}: ${topApps}`;
}

function isStaleProcessing(value) {
  if (!value || typeof value.toDate !== "function") return true;
  const processingAgeMs = Date.now() - value.toDate().getTime();
  return processingAgeMs > 5 * 60 * 1000;
}

function shutdown() {
  if (notificationUnsubscribe) notificationUnsubscribe();
  if (activityUnsubscribe) activityUnsubscribe();
  if (dailySummaryTimer) clearInterval(dailySummaryTimer);
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);









