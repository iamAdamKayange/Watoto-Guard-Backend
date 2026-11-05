import { z } from "zod";
import { canUseAiGuardian, resolveAiAssistantConfiguration } from "./ai_guardian";

export type GuardianVoiceLanguage = "sw" | "en";
export type GuardianVoiceGender = "male" | "female";

export const guardianVoiceInputSchema = z.object({
  text: z.string().trim().min(1).max(3000),
  language: z.enum(["sw", "en"]),
  gender: z.enum(["male", "female"]),
  rate: z.number().min(0.75).max(1.25).default(1),
}).strict();

export const guardianTranscriptionSchema = z.object({ language: z.enum(["sw", "en", "auto"]).default("auto") }).strict();

export async function guardianVoiceAuthorizationAllowed(input: {
  role: Parameters<typeof canUseAiGuardian>[0];
  schoolId: string | null;
  enabled: boolean;
  childId?: string;
  hasChildAccess: (childId: string) => Promise<boolean>;
}) {
  if (!input.enabled || !canUseAiGuardian(input.role, input.schoolId)) return false;
  return !input.childId || await input.hasChildAccess(input.childId);
}

export class GuardianVoiceError extends Error {
  constructor(readonly code: "voice_not_configured" | "voice_provider_timeout" | "voice_unavailable" | "voice_invalid_response" | "voice_cancelled") {
    super(code);
    this.name = "GuardianVoiceError";
  }
}

type ServiceRequest = {
  host?: string;
  secret?: string;
  fetcher?: typeof fetch;
  signal?: AbortSignal;
};

function getConfiguration(host: string | undefined, secret: string | undefined) {
  const config = resolveAiAssistantConfiguration(host, secret);
  if (!config.ok) throw new GuardianVoiceError("voice_not_configured");
  return config;
}

async function serviceRequest(input: ServiceRequest, path: string, body: FormData) {
  const config = getConfiguration(input.host, input.secret);
  try {
    const response = await (input.fetcher ?? fetch)(`${config.serviceUrl}/${path}`, {
      method: "POST",
      signal: input.signal ? AbortSignal.any([AbortSignal.timeout(105_000), input.signal]) : AbortSignal.timeout(105_000),
      headers: { "X-KidGuard-AI-Secret": config.sharedSecret },
      body,
    });
    return response;
  } catch (error) {
    throw new GuardianVoiceError(error instanceof Error && error.name === "TimeoutError" ? "voice_provider_timeout" : error instanceof Error && error.name === "AbortError" ? "voice_cancelled" : "voice_unavailable");
  }
}

export async function transcribeGuardianVoice(input: ServiceRequest & {
  audio: Uint8Array;
  language: "sw" | "en" | "auto";
}) {
  const form = new FormData();
  form.append("audio", new Blob([new Uint8Array(input.audio)], { type: "audio/wav" }), "voice.wav");
  form.append("language", input.language);
  const response = await serviceRequest(input, "v1/transcribe", form);
  if (!response.ok) throw new GuardianVoiceError(response.status === 504 ? "voice_provider_timeout" : "voice_unavailable");
  let result: { transcript?: unknown; language?: unknown };
  try { result = await response.json() as typeof result; }
  catch { throw new GuardianVoiceError("voice_invalid_response"); }
  const transcript = typeof result.transcript === "string" ? result.transcript.trim() : "";
  if (!transcript || transcript.length > 3000 || (result.language !== "sw" && result.language !== "en" && result.language !== "auto")) {
    throw new GuardianVoiceError("voice_invalid_response");
  }
  return { transcript, language: result.language };
}

export async function synthesizeGuardianVoice(input: ServiceRequest & z.infer<typeof guardianVoiceInputSchema>) {
  const form = new FormData();
  form.append("text", input.text);
  form.append("language", input.language);
  form.append("gender", input.gender);
  form.append("rate", String(input.rate));
  const response = await serviceRequest(input, "v1/synthesize", form);
  if (!response.ok) throw new GuardianVoiceError(response.status === 504 ? "voice_provider_timeout" : "voice_unavailable");
  if (!(response.headers.get("content-type") ?? "").toLowerCase().includes("audio/wav")) {
    throw new GuardianVoiceError("voice_invalid_response");
  }
  const audio = new Uint8Array(await response.arrayBuffer());
  if (!audio.length || audio.length > 8 * 1024 * 1024 || audio[0] !== 0x52 || audio[1] !== 0x49 || audio[2] !== 0x46 || audio[3] !== 0x46) {
    throw new GuardianVoiceError("voice_invalid_response");
  }
  return audio;
}
