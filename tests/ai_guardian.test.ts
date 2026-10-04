import assert from "node:assert/strict";
import test from "node:test";
import { buildConversationWindow, canUseAiGuardian, classifyNotificationVoice, classifySafetyVoice, cleanContextText, ownedConversationWhere, requestOpenAi, validateChatMessages } from "../src/ai_guardian";

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

test("provider requests do not persist response state and extract the Responses API text", async () => {
  let requestBody: Record<string, unknown> = {};
  const answer = await requestOpenAi({
    apiKey: "test-key", model: "test-model", language: "sw", messages: [{ role: "user", content: "Attendance?" }], context: { attendance: [] },
    fetcher: async (_input, init) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ output_text: "Taarifa haipo." }), { status: 200 });
    },
  });
  assert.equal(answer, "Taarifa haipo.");
  assert.equal(requestBody.store, false);
  assert.equal(requestBody.model, "test-model");
});

test("provider failures are surfaced without returning provider response details", async () => {
  await assert.rejects(() => requestOpenAi({
    apiKey: "test-key", model: "test-model", language: "sw", messages: [{ role: "user", content: "x" }], context: {},
    fetcher: async () => new Response("secret provider body", { status: 503 }),
  }), /status 503/);
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
