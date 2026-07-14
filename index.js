const express = require("express");
const admin = require("firebase-admin");

const port = process.env.PORT || 10000;
const lookbackMinutes = Number(process.env.LISTENER_LOOKBACK_MINUTES || 120);
const startedAt = new Date(Date.now() - lookbackMinutes * 60 * 1000);

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

app.get("/", (_, response) => {
  response.json({
    ok: true,
    service: "watoto-guard-notification-worker",
    startedAt: startedAt.toISOString(),
    notificationEventsSeen,
    activityEventsSeen,
    lastNotificationAt,
    lastActivityAt,
  });
});

app.get("/health", (_, response) => {
  response.json({ ok: true });
});

app.listen(port, () => {
  console.log(`WatotoGuard notification worker listening on ${port}`);
  startListeners();
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

  const recipients = new Map();
  const baseData = {
    source: type === "blocked_content" ? "blocked_content" : "app_usage",
    activityId: snapshot.id,
    childId,
    deviceId: stringOrDefault(activity.deviceId, ""),
  };

  if (type === "app_usage_summary" && parentId && typeof parentId === "string") {
    recipients.set(parentId, {
      role: "parent",
      title: "Child app usage update",
      body: buildAppUsageBody(deviceName, activity.apps),
    });
  }

  const teacherSnapshot = await db
    .collection("users")
    .where("studentIds", "array-contains", childId)
    .get();

  teacherSnapshot.docs.forEach((teacherDoc) => {
    const teacher = teacherDoc.data() || {};
    if (teacher.role !== "teacher") return;
    recipients.set(teacherDoc.id, {
      role: "teacher",
      title: type === "blocked_content"
        ? "Student unsafe content blocked"
        : "Student app usage update",
      body: type === "blocked_content"
        ? `${deviceName} blocked: ${stringOrDefault(activity.blockedTerm, "unsafe content")}`
        : buildAppUsageBody(deviceName, activity.apps),
    });
  });

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
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
