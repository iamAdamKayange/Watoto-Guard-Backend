import { z } from "zod";

export type GuardianVoiceLanguage = "sw" | "en";
export type GuardianVoiceGender = "male" | "female";
export const guardianVoiceInputSchema = z.object({
  text: z.string().trim().min(1).max(3000), language: z.enum(["sw", "en"]),
  gender: z.enum(["male", "female"]), rate: z.number().min(0.75).max(1.25).default(1),
}).strict();

export const GUARDIAN_VOICES = {
  sw: { female: { locale: "sw-TZ", name: "sw-TZ-RehemaNeural" }, male: { locale: "sw-TZ", name: "sw-TZ-DaudiNeural" } },
  en: { female: { locale: "en-TZ", name: "en-TZ-ImaniNeural" }, male: { locale: "en-TZ", name: "en-TZ-ElimuNeural" } },
} as const;

export class GuardianVoiceError extends Error {
  constructor(readonly code: "voice_not_configured" | "voice_provider_timeout" | "voice_unavailable" | "voice_invalid_response") {
    super(code);
    this.name = "GuardianVoiceError";
  }
}

export type GuardianSpeechRequest = {
  key?: string;
  region?: string;
  text: string;
  language: GuardianVoiceLanguage;
  gender: GuardianVoiceGender;
  rate: number;
  fetcher?: typeof fetch;
};

export interface GuardianSpeechProvider {
  synthesize(input: GuardianSpeechRequest): Promise<Uint8Array>;
}

export function escapeSsmlText(value: string) {
  return value.replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&apos;" })[character]!);
}

export class AzureGuardianSpeechProvider implements GuardianSpeechProvider {
  async synthesize(input: GuardianSpeechRequest): Promise<Uint8Array> {
  const key = input.key?.trim();
  const region = input.region?.trim();
  if (!key || !region || !/^[a-z0-9-]{2,30}$/i.test(region)) throw new GuardianVoiceError("voice_not_configured");
  const voice = GUARDIAN_VOICES[input.language][input.gender];
  const percent = Math.round(Math.min(1.25, Math.max(0.75, input.rate)) * 100);
  const ssml = `<speak version="1.0" xml:lang="${voice.locale}"><voice name="${voice.name}"><prosody rate="${percent}%">${escapeSsmlText(input.text)}</prosody></voice></speak>`;
  let response: Response;
  try {
    response = await (input.fetcher ?? fetch)(`https://${region}.tts.speech.microsoft.com/cognitiveservices/v1`, {
      method: "POST",
      signal: AbortSignal.timeout(20_000),
      headers: {
        "Ocp-Apim-Subscription-Key": key,
        "Content-Type": "application/ssml+xml",
        "X-Microsoft-OutputFormat": "audio-24khz-160kbitrate-mono-mp3",
        "User-Agent": "KidGuard-Guardian-Voice",
      },
      body: ssml,
    });
  } catch (error) {
    throw new GuardianVoiceError(error instanceof Error && error.name === "TimeoutError" ? "voice_provider_timeout" : "voice_unavailable");
  }
  if (!response.ok) throw new GuardianVoiceError("voice_unavailable");
  const audio = new Uint8Array(await response.arrayBuffer());
  if (!audio.length || audio.length > 8 * 1024 * 1024) throw new GuardianVoiceError("voice_invalid_response");
    return audio;
  }
}

export const synthesizeGuardianVoice = (input: GuardianSpeechRequest) =>
  new AzureGuardianSpeechProvider().synthesize(input);
