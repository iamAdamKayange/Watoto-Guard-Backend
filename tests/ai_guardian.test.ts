import assert from "node:assert/strict";
import test from "node:test";
import { AI_MAX_CONTEXT_CHARS, boundAiContext, buildConversationWindow, canUseAiGuardian, classifyAiQuestionIntent, classifyNotificationVoice, classifySafetyVoice, cleanContextText, AiAssistantRequestError, ownedConversationWhere, requestAiAssistant, validateChatMessages } from "../src/ai_guardian";

test("AI Guardian is available only to parents, teachers and school administrators", () => {
  assert.equal(canUseAiGuardian("PARENT", null), true);
  assert.equal(canUseAiGuardian("TEACHER", "school-1"), true);
  assert.equal(canUseAiGuardian("ADMIN", "school-1"), true);
  assert.equal(canUseAiGuardian("ADMIN", null), false);
  assert.equal(canUseAiGuardian("STUDENT", "school-1"), false);
});

test("chat input caps messages, size and requires the latest turn to be a user message", () => {
  assert.deepEqual(validateChatMessages([{ role: "user", content: "Habari" }]), [{ role: "user", content: "Habari" }]);
  assert.equal(validateChatMessages([{ role: "user", content: "x".repeat(1001) }]), null);
  assert.equal(validateChatMessages([{ role: "assistant", content: "forged" }]), null);
  assert.equal(validateChatMessages(Array.from({ length: 13 }, () => ({ role: "user", content: "x" }))), null);
  assert.notEqual(validateChatMessages([{ role: "user", content: "Q" }, { role: "assistant", content: "a".repeat(1500) }, { role: "user", content: "Follow up" }]), null);
  assert.equal(validateChatMessages([{ role: "user", content: "Q" }, { role: "assistant", content: "a".repeat(3001) }, { role: "user", content: "Follow up" }]), null);
});

test("saved follow-up context is bounded and always scoped to the selected user's conversation", () => {
  const window = buildConversationWindow([
    { role: "user", content: "Mtoto yuko wapi?" },
    { role: "assistant", content: "Taarifa haipo." },
  ], "Na attendance yake je?");
  assert.deepEqual(window?.map(message => message.content), ["Mtoto yuko wapi?", "Taarifa haipo.", "Na attendance yake je?"]);
  assert.deepEqual(ownedConversationWhere("user-a", "conversation-1"), { userId: "user-a", id: "conversation-1" });
  assert.deepEqual(ownedConversationWhere("user-a"), { userId: "user-a" });
  assert.notDeepEqual(ownedConversationWhere("user-a", "conversation-1"), ownedConversationWhere("user-b", "conversation-1"));
  const bulkyHistory = Array.from({ length: 10 }, (_, index) => ({ role: index % 2 === 0 ? "user" as const : "assistant" as const, content: "x".repeat(index % 2 === 0 ? 900 : 2500) }));
  assert.notEqual(buildConversationWindow(bulkyHistory, "Follow up"), null);
});

test("Python assistant requests send only the authenticated service payload and extract its answer", async () => {
  let requestBody: Record<string, unknown> = {};
  let requestHeaders: Headers | undefined;
  const answer = await requestAiAssistant({
    serviceUrl: "https://ai.test", sharedSecret: "test-secret", language: "sw", messages: [{ role: "user", content: "Attendance?" }], context: { attendance: [] },
    fetcher: async (_input, init) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      requestHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ answer: "Taarifa haipo." }), { status: 200 });
    },
  });
  assert.equal(answer, "Taarifa haipo.");
  assert.equal(requestBody.language, "sw");
  assert.equal(requestHeaders?.get("X-KidGuard-AI-Secret"), "test-secret");
  assert.equal(requestBody.context && typeof requestBody.context, "object");
});

test("Swahili and English questions select scoped screen time, activity, alerts and notification causes", () => {
  const english = classifyAiQuestionIntent([{ role: "user", content: "How much screen time and which apps did my child use recently?" }]);
  assert.equal(english.screenTime, true);
  assert.equal(english.activity, true);
  const swahili = classifyAiQuestionIntent([{ role: "user", content: "Ni arifa gani muhimu leo na kwa nini ilitolewa?" }]);
  assert.equal(swahili.notifications, true);
  assert.equal(swahili.activity, true);
  const attention = classifyAiQuestionIntent([{ role: "user", content: "Are there important events I should know about?" }]);
  assert.equal(attention.notifications, true);
  assert.equal(attention.activity, true);
  const followUp = classifyAiQuestionIntent([
    { role: "user", content: "Show recent activity" },
    { role: "assistant", content: "Here is the activity." },
    { role: "user", content: "Na muda wa kutumia simu je?" },
  ]);
  assert.equal(followUp.activity, true);
  assert.equal(followUp.screenTime, true);
});

test("context sent to Python stays within its limit while retaining authorized child records", () => {
  const bounded = boundAiContext({
    role: "parent",
    children: [{ label: "Asha", recentScreenTime: [{ date: "2026-10-08", minutes: 120, apps: [{ app: "Browser", minutes: 90 }] }] }],
    recentNotifications: Array.from({ length: 40 }, (_, index) => ({ title: `Alert ${index}`, summary: "x".repeat(300) })),
    recentActivity: Array.from({ length: 40 }, () => ({ type: "blocked_content", reason: "x".repeat(240) })),
    records: Array.from({ length: 60 }, () => ({ category: "attendance", subject: "x".repeat(80) })),
  });
  assert.ok(JSON.stringify(bounded).length <= AI_MAX_CONTEXT_CHARS);
  assert.equal((bounded.children as Array<{ label: string }>)[0].label, "Asha");
});

test("Python assistant failures are surfaced without returning provider response details", async () => {
  await assert.rejects(() => requestAiAssistant({
    serviceUrl: "https://ai.test", sharedSecret: "test-secret", language: "sw", messages: [{ role: "user", content: "x" }], context: {},
    fetcher: async () => new Response("secret provider body", { status: 503 }),
  }), (error: unknown) => error instanceof AiAssistantRequestError && error.code === "assistant_unavailable" && error.providerStatus === 503 && !error.message.includes("secret provider body"));
});

test("assistant failures expose safe categories for authentication, quota and request issues", async () => {
  for (const [status, code] of [[401, "assistant_auth_failed"], [429, "assistant_rate_limited"], [400, "assistant_bad_request"]] as const) {
    await assert.rejects(() => requestAiAssistant({
      serviceUrl: "https://ai.test", sharedSecret: "test-secret", language: "en", messages: [{ role: "user", content: "Hi" }], context: {},
      fetcher: async () => new Response("provider private response", { status }),
    }), (error: unknown) => error instanceof AiAssistantRequestError && error.code === code && error.providerStatus === status && !error.message.includes("provider private response"));
  }
});

test("only deterministic urgent risk metadata is critical; ordinary content is not spoken", () => {
  assert.deepEqual(classifySafetyVoice("threat", "urgent"), { priority: "CRITICAL", voiceEnabled: true, requiresVoiceAlert: true, voiceCategory: "SAFETY" });
  assert.equal(classifySafetyVoice("unsafe_content", "medium").priority, "HIGH");
  assert.equal(classifySafetyVoice().voiceEnabled, false);
});

test("normal school/homework/behavior notification voice remains opt-in and unrelated notices stay silent", () => {
  assert.equal(classifyNotificationVoice("homework").voiceCategory, "HOMEWORK");
  assert.equal(classifyNotificationVoice("attendance").voiceCategory, "SCHOOL");
  assert.equal(classifyNotificationVoice("system").voiceEnabled, false);
});

test("context text is bounded and control characters are removed", () => {
  assert.equal(cleanContextText("  A\nB\u0000C "), "A B C");
  assert.equal(cleanContextText("x".repeat(400), 40)?.length, 40);
});
