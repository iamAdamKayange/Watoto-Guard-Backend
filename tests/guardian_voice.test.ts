import assert from "node:assert/strict";
import test from "node:test";
import { guardianTranscriptionSchema, guardianVoiceAuthorizationAllowed, guardianVoiceInputSchema, GuardianVoiceError, synthesizeGuardianVoice, transcribeGuardianVoice } from "../src/guardian_voice";

const base = { host: "https://kidguard-ai-assistant.onrender.com", secret: "s".repeat(40) };

test("voice requests validate bounded text, language, gender, audio language and unknown fields", () => {
  assert.equal(guardianVoiceInputSchema.safeParse({ text: " ", language: "sw", gender: "female" }).success, false);
  assert.equal(guardianVoiceInputSchema.safeParse({ text: "x".repeat(3001), language: "en", gender: "male" }).success, false);
  assert.equal(guardianVoiceInputSchema.safeParse({ text: "Hello", language: "en", gender: "other" }).success, false);
  assert.equal(guardianVoiceInputSchema.safeParse({ text: "Hello", language: "en", gender: "male", voiceId: "arbitrary" }).success, false);
  assert.deepEqual(guardianVoiceInputSchema.parse({ text: " Hello ", language: "en", gender: "male" }), { text: "Hello", language: "en", gender: "male", rate: 1 });
  assert.equal(guardianTranscriptionSchema.safeParse({ language: "auto" }).success, true);
  assert.equal(guardianTranscriptionSchema.safeParse({ language: "fr" }).success, false);
});

test("the authenticated parent must have AI enabled and access an optional child id", async () => {
  const hasChildAccess = async (childId: string) => childId === "authorized-child";
  assert.equal(await guardianVoiceAuthorizationAllowed({ role: "PARENT", schoolId: null, enabled: true, childId: "authorized-child", hasChildAccess }), true);
  assert.equal(await guardianVoiceAuthorizationAllowed({ role: "PARENT", schoolId: null, enabled: true, childId: "other-child", hasChildAccess }), false);
  assert.equal(await guardianVoiceAuthorizationAllowed({ role: "PARENT", schoolId: null, enabled: false, childId: "authorized-child", hasChildAccess }), false);
  assert.equal(await guardianVoiceAuthorizationAllowed({ role: "ADMIN", schoolId: null, enabled: true, hasChildAccess }), false);
});

test("transcription sends only multipart audio and the internal shared-secret header", async () => {
  let requestOptions: RequestInit | undefined;
  const result = await transcribeGuardianVoice({
    ...base, audio: Uint8Array.from([1, 2, 3]), language: "sw",
    fetcher: async (url, init) => {
      assert.equal(url, `${base.host}/v1/transcribe`);
      requestOptions = init;
      return Response.json({ transcript: "Mtoto ametumia kifaa", language: "sw" });
    },
  });
  assert.deepEqual(result, { transcript: "Mtoto ametumia kifaa", language: "sw" });
  assert.equal((requestOptions?.headers as Record<string, string>)["X-KidGuard-AI-Secret"], base.secret);
  const form = requestOptions?.body as FormData;
  assert.equal(form.get("language"), "sw");
  assert.equal((form.get("audio") as File).name, "voice.wav");
});

test("synthesis requests Python Piper and validates a WAV response", async () => {
  let requestOptions: RequestInit | undefined;
  const bytes = await synthesizeGuardianVoice({
    ...base, text: "Habari", language: "sw", gender: "male", rate: 1.1,
    fetcher: async (_url, init) => {
      requestOptions = init;
      return new Response(Uint8Array.from([0x52, 0x49, 0x46, 0x46, 1, 2]), { headers: { "Content-Type": "audio/wav" } });
    },
  });
  assert.deepEqual([...bytes], [0x52, 0x49, 0x46, 0x46, 1, 2]);
  assert.equal((requestOptions?.headers as Record<string, string>)["X-KidGuard-AI-Secret"], base.secret);
  const form = requestOptions?.body as FormData;
  assert.equal(form.get("text"), "Habari");
  assert.equal(form.get("gender"), "male");
  assert.equal(form.get("rate"), "1.1");
});

test("voice integration fails safely on missing config, timeout, cancellation, bad HTTP and malformed results", async () => {
  await assert.rejects(() => transcribeGuardianVoice({ audio: Uint8Array.from([1]), language: "en" }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_not_configured");
  await assert.rejects(() => transcribeGuardianVoice({ ...base, audio: Uint8Array.from([1]), language: "en", fetcher: async () => { throw Object.assign(new Error("timeout"), { name: "TimeoutError" }); } }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_provider_timeout");
  await assert.rejects(() => transcribeGuardianVoice({ ...base, audio: Uint8Array.from([1]), language: "en", fetcher: async () => { throw Object.assign(new Error("cancelled"), { name: "AbortError" }); } }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_cancelled");
  await assert.rejects(() => transcribeGuardianVoice({ ...base, audio: Uint8Array.from([1]), language: "en", fetcher: async () => new Response("private data", { status: 401 }) }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_unavailable" && !error.message.includes("private"));
  await assert.rejects(() => transcribeGuardianVoice({ ...base, audio: Uint8Array.from([1]), language: "en", fetcher: async () => Response.json({ transcript: "", language: "en" }) }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_invalid_response");
  await assert.rejects(() => synthesizeGuardianVoice({ ...base, text: "hello", language: "en", gender: "female", rate: 1, fetcher: async () => new Response("not audio", { headers: { "Content-Type": "application/json" } }) }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_invalid_response");
});
