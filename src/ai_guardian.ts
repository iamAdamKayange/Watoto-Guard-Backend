export type ChatMessage = { role: "user" | "assistant"; content: string };

export class AiAssistantRequestError extends Error {
  constructor(readonly code: string, readonly providerStatus?: number) {
    super(code);
    this.name = "AiAssistantRequestError";
  }
}

export const AI_MAX_HISTORY_MESSAGES = 12;
export const AI_MAX_MESSAGE_CHARS = 1000;
export const AI_MAX_ASSISTANT_CHARS = 3000;
export const AI_MAX_TOTAL_CHARS = 6000;
export const AI_MAX_REQUESTS_PER_MINUTE = 8;

export function classifySafetyVoice(riskCategory?: string, severity?: string) {
  const classified = ["self_harm", "threat", "bullying", "unsafe_content"].includes(riskCategory ?? "") && ["low", "medium", "high", "urgent"].includes(severity ?? "");
  const priority = severity === "urgent" && classified ? "CRITICAL" : classified ? "HIGH" : "NORMAL";
  const voiceCategory = riskCategory === "self_harm" || riskCategory === "threat" ? "SAFETY" : riskCategory === "bullying" ? "BEHAVIOR" : "GENERAL";
  return { priority, voiceEnabled: classified, requiresVoiceAlert: priority === "CRITICAL", voiceCategory };
}

export function classifyNotificationVoice(type: string) {
  const category = type.toLowerCase();
  if (["attendance", "announcement", "result"].includes(category)) return { priority: "NORMAL", voiceEnabled: true, requiresVoiceAlert: false, voiceCategory: "SCHOOL" };
  if (category === "homework") return { priority: "NORMAL", voiceEnabled: true, requiresVoiceAlert: false, voiceCategory: "HOMEWORK" };
  if (category === "behavior") return { priority: "NORMAL", voiceEnabled: true, requiresVoiceAlert: false, voiceCategory: "BEHAVIOR" };
  return { priority: "NORMAL", voiceEnabled: false, requiresVoiceAlert: false, voiceCategory: "GENERAL" };
}

export function validateChatMessages(input: unknown): ChatMessage[] | null {
  if (!Array.isArray(input) || input.length === 0 || input.length > AI_MAX_HISTORY_MESSAGES) return null;
  const messages: ChatMessage[] = [];
  let total = 0;
  for (const value of input) {
    if (!value || typeof value !== "object") return null;
    const row = value as Record<string, unknown>;
    if ((row.role !== "user" && row.role !== "assistant") || typeof row.content !== "string") return null;
    const content = row.content.trim();
    if (!content || content.length > (row.role === "user" ? AI_MAX_MESSAGE_CHARS : AI_MAX_ASSISTANT_CHARS)) return null;
    total += content.length;
    if (total > AI_MAX_TOTAL_CHARS) return null;
    messages.push({ role: row.role, content });
  }
  if (messages[0]?.role !== "user" || messages[messages.length - 1]?.role !== "user") return null;
  for (let index = 1; index < messages.length; index += 1) {
    if (messages[index].role === messages[index - 1].role) return null;
  }
  return messages;
}

export function canUseAiGuardian(role: string, schoolId: string | null | undefined): boolean {
  return role === "PARENT" || role === "TEACHER" || (role === "ADMIN" && !!schoolId);
}

export function ownedConversationWhere(userId: string, conversationId?: string) {
  return conversationId ? { userId, id: conversationId } : { userId };
}

export function buildConversationWindow(previous: ChatMessage[], currentMessage: string): ChatMessage[] | null {
  const history = previous.slice(-10).map(message => ({ ...message }));
  while (history.length && history[0].role !== "user") history.shift();
  while (history.length) {
    const window = validateChatMessages([...history, { role: "user", content: currentMessage }]);
    if (window) return window;
    history.splice(0, 2);
    while (history.length && history[0].role !== "user") history.shift();
  }
  return validateChatMessages([{ role: "user", content: currentMessage }]);
}

export function cleanContextText(value: unknown, max = 120): string | undefined {
  if (typeof value !== "string") return undefined;
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max) || undefined;
}

export function classifyAiQuestionIntent(messages: ChatMessage[]) {
  const question = messages.filter(message => message.role === "user").slice(-6).map(message => message.content).join(" ").normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();
  const summary = /\b(summary|muhtasari|overview|ripoti ya jumla)\b/.test(question);
  const screenTime = summary || /\b(screen.?time|usage|matumizi ya simu|muda wa simu|muda wa kutumia simu|ametumia simu|apps?|application|programu)\b/.test(question);
  const notifications = /\b(notification|notifications|arifa|alert|alerts|tahadhari|muhimu|important|attention|concern|should know|need to know|pay attention|nifuatilie|niangalie|nifahamu|kuna jambo|kuna nini|generated|generated reason|kwa nini|sababu ya|imetokeaje)\b/.test(question);
  const activity = summary || /\b(activity|activities|recent|recently|hivi karibuni|shughuli|matukio|kilichotokea|kimetokea|yaliyotokea|kilichofanyika|what happened|anything happened|events?|muhimu|important|attention|should know|need to know|pay attention|kuna jambo|nifuatilie|nifahamu)\b/.test(question);
  return {
    summary,
    screenTime,
    notifications,
    activity,
    location: summary || /\b(location|where|wapi|mahali|alipo|ramani)\b/.test(question),
    attendance: summary || /\b(attendance|mahudhurio|hudhuria|amekuja|hakufika|absent|present)\b/.test(question),
    homework: summary || /\b(homework|assignment|kazi za shule|kazi ya shule)\b/.test(question),
    behavior: summary || /\b(behavior|tabia|bully|bullying|vitisho|safety|usalama|hatari)\b/.test(question),
    results: summary || /\b(results?|matokeo|marks|score|grade|alama)\b/.test(question),
    school: summary || /\b(school|shule|announcement|tangazo|taarifa za shule)\b/.test(question),
    devices: summary || /\b(device|kifaa|connected|imeunganishwa|online|offline|monitoring|ufuatiliaji)\b/.test(question),
  };
}

export const AI_MAX_CONTEXT_CHARS = 12_000;

export function boundAiContext(input: Record<string, unknown>): Record<string, unknown> {
  const context = JSON.parse(JSON.stringify(input)) as Record<string, unknown>;
  const encodedLength = () => JSON.stringify(context).length;
  while (encodedLength() > AI_MAX_CONTEXT_CHARS) {
    const trimLast = (key: string) => {
      const value = context[key];
      if (!Array.isArray(value) || value.length === 0) return false;
      value.pop();
      return true;
    };
    // Keep the newest/highest-signal items and discard older tail entries first.
    if (trimLast("records") || trimLast("recentActivity") || trimLast("recentNotifications")) continue;
    const children = context.children;
    if (Array.isArray(children)) {
      let trimmedNested = false;
      for (const rawChild of children) {
        if (!rawChild || typeof rawChild !== "object" || Array.isArray(rawChild)) continue;
        const child = rawChild as Record<string, unknown>;
        const days = child.recentScreenTime;
        if (Array.isArray(days) && days.length) {
          const latestDay = days[days.length - 1] as Record<string, unknown>;
          if (Array.isArray(latestDay?.apps) && latestDay.apps.length) latestDay.apps.pop();
          else days.pop();
          trimmedNested = true;
          break;
        }
      }
      if (trimmedNested) continue;
      if (children.length) { children.pop(); continue; }
    }
    const schools = context.schools;
    if (Array.isArray(schools) && schools.length) { schools.pop(); continue; }
    break;
  }
  return context;
}

export async function requestAiAssistant(input: {
  serviceUrl: string;
  sharedSecret: string;
  messages: ChatMessage[];
  context: unknown;
  language: string;
  fetcher?: typeof fetch;
}): Promise<string> {
  let response: Response;
  try {
    response = await (input.fetcher ?? fetch)(`${input.serviceUrl.replace(/\/$/, "")}/v1/answer`, {
    method: "POST",
    signal: AbortSignal.timeout(25_000),
    headers: { "X-KidGuard-AI-Secret": input.sharedSecret, "Content-Type": "application/json" },
    body: JSON.stringify({
      language: input.language,
      messages: input.messages,
      context: input.context,
    }),
    });
  } catch (error) {
    throw new AiAssistantRequestError(error instanceof Error && error.name === "TimeoutError" ? "assistant_timeout" : "assistant_network_error");
  }
  if (!response.ok) {
    const code = response.status === 401 || response.status === 403 ? "assistant_auth_failed"
      : response.status === 429 ? "assistant_rate_limited"
      : response.status === 400 ? "assistant_bad_request"
      : response.status >= 500 ? "assistant_unavailable" : "assistant_request_failed";
    throw new AiAssistantRequestError(code, response.status);
  }
  let payload: { answer?: unknown };
  try { payload = await response.json() as typeof payload; }
  catch { throw new AiAssistantRequestError("assistant_invalid_response", response.status); }
  const result = typeof payload.answer === "string" ? payload.answer.trim() : "";
  if (!result) throw new AiAssistantRequestError("assistant_invalid_response", response.status);
  return result.slice(0, 3000);
}
