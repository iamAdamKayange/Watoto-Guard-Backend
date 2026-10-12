import assert from "node:assert/strict";
import test from "node:test";
import { guardianVoiceInputSchema, GuardianVoiceError, GUARDIAN_VOICES, synthesizeGuardianVoice } from "../src/guardian_voice";

test("voice routing uses the verified Tanzania locales for Kiswahili and English genders", () => {
  assert.equal(GUARDIAN_VOICES.sw.female.name, "sw-TZ-RehemaNeural");
  assert.equal(GUARDIAN_VOICES.sw.male.name, "sw-TZ-DaudiNeural");
  assert.equal(GUARDIAN_VOICES.en.female.name, "en-TZ-ImaniNeural");
  assert.equal(GUARDIAN_VOICES.en.male.name, "en-TZ-ElimuNeural");
  assert.equal(GUARDIAN_VOICES.en.male.locale, "en-TZ");
});

test("speech input rejects empty, oversized, out-of-range, and unrecognized client voice values", () => {
  assert.equal(guardianVoiceInputSchema.safeParse({ text: " ", language: "sw", gender: "female" }).success, false);
  assert.equal(guardianVoiceInputSchema.safeParse({ text: "x".repeat(3001), language: "en", gender: "male" }).success, false);
  assert.equal(guardianVoiceInputSchema.safeParse({ text: "Hello", language: "en", gender: "other" }).success, false);
  assert.equal(guardianVoiceInputSchema.safeParse({ text: "Hello", language: "en", gender: "male", voiceId: "arbitrary" }).success, false);
  assert.deepEqual(guardianVoiceInputSchema.parse({ text: " Hello ", language: "en", gender: "male" }), { text: "Hello", language: "en", gender: "male", rate: 1 });
});

test("Azure request contains escaped text and constrained voice settings but never exposes credentials in errors", async () => {
  let options: RequestInit | undefined;
  const bytes = await synthesizeGuardianVoice({
    key: "private-key", region: "eastus", text: "Asha & <Baraka>", language: "sw", gender: "female", rate: 1.1,
    fetcher: async (_url, init) => { options = init; return new Response(Uint8Array.from([1, 2, 3]), { status: 200 }); },
  });
  assert.deepEqual([...bytes], [1, 2, 3]);
  assert.equal((options?.headers as Record<string, string>)["Ocp-Apim-Subscription-Key"], "private-key");
  assert.match(String(options?.body), /sw-TZ-RehemaNeural/);
  assert.match(String(options?.body), /Asha &amp; &lt;Baraka&gt;/);
  assert.match(String(options?.body), /rate="110%"/);
});

test("Azure speech fails safely for missing credentials, timeouts, unavailable voices and invalid audio", async () => {
  const base = { text: "Habari", language: "sw" as const, gender: "male" as const, rate: 1 };
  await assert.rejects(() => synthesizeGuardianVoice({ ...base }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_not_configured");
  await assert.rejects(() => synthesizeGuardianVoice({ ...base, key: "key", region: "bad/region" }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_not_configured");
  await assert.rejects(() => synthesizeGuardianVoice({ ...base, key: "key", region: "eastus", fetcher: async () => { throw Object.assign(new Error("timeout"), { name: "TimeoutError" }); } }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_provider_timeout" && !error.message.includes("key"));
  await assert.rejects(() => synthesizeGuardianVoice({ ...base, key: "key", region: "eastus", fetcher: async () => new Response("secret provider detail", { status: 400 }) }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_unavailable" && !error.message.includes("secret"));
  await assert.rejects(() => synthesizeGuardianVoice({ ...base, key: "key", region: "eastus", fetcher: async () => new Response(new Uint8Array()) }), (error: unknown) => error instanceof GuardianVoiceError && error.code === "voice_invalid_response");
});
