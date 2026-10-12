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

export type AiAssistantConfiguration =
  | { ok: true; serviceUrl: string; sharedSecret: string }
  | { ok: false; code: "ai_host_missing" | "ai_host_invalid" | "ai_secret_missing" | "ai_secret_too_short" };

/** Validate deployment configuration without including secret values in errors. */
export function resolveAiAssistantConfiguration(
  hostValue: string | undefined,
  secretValue: string | undefined,
): AiAssistantConfiguration {
  const host = hostValue?.trim();
  const sharedSecret = secretValue?.trim();
  if (!host) return { ok: false, code: "ai_host_missing" };
  if (!sharedSecret) return { ok: false, code: "ai_secret_missing" };
  if (sharedSecret.length < 32) return { ok: false, code: "ai_secret_too_short" };

  let url: URL;
  try {
    url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(host) ? host : `https://${host}`);
  } catch {
    return { ok: false, code: "ai_host_invalid" };
  }
  const isLocalHost = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  if (!(["https:", "http:"].includes(url.protocol)) ||
      (url.protocol === "http:" && !isLocalHost) ||
      !!url.username || !!url.password || !!url.search || !!url.hash ||
      (url.pathname !== "/" && url.pathname !== "")) {
    return { ok: false, code: "ai_host_invalid" };
  }
  return { ok: true, serviceUrl: url.origin, sharedSecret };
}

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
  const features = /\b(feature|features|how do i|how can i|what can kidguard|what does kidguard|vipengele|nawezaje|natumiaje)\b/.test(question);
  const profile = /\b(my account|my profile|my name|my role|account status|akaunti yangu|wasifu wangu|jina langu|hali ya akaunti)\b/.test(question);
  const settings = /\b(settings|preferences|mipangilio|mapendeleo|language|theme|voice preferences|app language|lugha ya programu|lugha ya app|muonekano|sauti ninayotumia)\b/.test(question);
  const subscription = /\b(subscription|premium|plan|billing|usajili|malipo|mpango)\b/.test(question);
  const linking = /\b(link|linked|pair|pairing|register|registration|qr code|unlink|unganisha|kuunganisha|usajili wa kifaa)\b/.test(question);
  const audit = /\b(when did|history|account activity|lini|historia ya akaunti|shughuli za akaunti)\b/.test(question);
  const screenTime = summary || /\b(screen.?time|usage|matumizi ya simu|muda wa simu|muda wa kutumia simu|ametumia simu|apps?|application|programu)\b/.test(question);
  const notifications = /\b(notification|notifications|arifa|alert|alerts|tahadhari|muhimu|important|attention|concern|should know|need to know|pay attention|nifuatilie|niangalie|nifahamu|kuna jambo|kuna nini|generated|generated reason|kwa nini|sababu ya|imetokeaje)\b/.test(question);
  const activity = summary || /\b(activity|activities|recent|recently|hivi karibuni|shughuli|matukio|kilichotokea|kimetokea|yaliyotokea|kilichofanyika|what happened|anything happened|events?|muhimu|important|attention|should know|need to know|pay attention|kuna jambo|nifuatilie|nifahamu)\b/.test(question);
  return {
    summary,
    features,
    profile,
    settings,
    subscription,
    linking,
    audit,
    screenTime,
    notifications,
    activity,
    location: summary || /\b(location|where|wapi|mahali|alipo|ramani)\b/.test(question),
    attendance: summary || /\b(attendance|mahudhurio|hudhuria|amekuja|hakufika|absent|present)\b/.test(question),
    homework: summary || /\b(homework|assignment|kazi za shule|kazi ya shule)\b/.test(question),
    behavior: summary || /\b(behavior|tabia|bully|bullying|vitisho|safety|usalama|hatari)\b/.test(question),
    results: summary || /\b(results?|matokeo|marks|score|grade|alama)\b/.test(question),
    school: summary || /\b(school|shule|announcement|tangazo|taarifa za shule)\b/.test(question),
    devices: summary || /\b(device|kifaa|connected|imeunganishwa|online|offline|monitoring|ufuatiliaji|permission|permissions|accessibility|usage access|background|izin|ufikiaji)\b/.test(question),
  };
}

/** Static descriptions of shipped features only; no roadmap claims. */
export function kidGuardFeatureCatalogue(role: string, platform = "android") {
  const common = [
    { feature: "AI Guardian", purpose: "Ask about authorized child and school data; availability depends on account settings and server configuration.", location: "Home → KidGuard AI" },
    { feature: "Notifications", purpose: "View alerts delivered to this account.", location: "Home → Notifications" },
    { feature: "Profile and settings", purpose: "Edit allowed personal fields and manage language, theme and notification preferences.", location: "Profile / Settings" },
  ];
  const byRole: Record<string, Array<{ feature: string; purpose: string; location: string }>> = {
    PARENT: [
      { feature: "Child profiles and links", purpose: "Register or link children and view their linked records.", location: "Home → Children" },
      { feature: "Child device monitoring", purpose: "Pair Android devices and view reported usage, screen time, protection state and latest heartbeat.", location: "Home → Monitoring" },
      { feature: "Safety terms", purpose: "Manage parent terms used by the paired Android local content matcher.", location: "Child monitoring → Safety terms" },
      { feature: "School records", purpose: "View available attendance, homework, published results and announcements for linked children.", location: "Home → School" },
      { feature: "Child location", purpose: "View a location only when sharing is enabled and the device has reported one.", location: "Home → Location" },
      { feature: "Subscription", purpose: "View the account subscription screen and recorded plan state.", location: "Profile → Subscription" },
    ],
    TEACHER: [
      { feature: "Assigned students", purpose: "View linked students and permitted school records.", location: "Home → Students" },
      { feature: "Class records", purpose: "Use available attendance, homework, behavior, results and announcement screens within assignment scope.", location: "Home → School" },
    ],
    ADMIN: [
      { feature: "School and class management", purpose: "Manage the assigned school, classes and authorized students.", location: "Home → School administration" },
      { feature: "Teacher invitations", purpose: "Invite teachers to the assigned school and view invitation status.", location: "Home → Teachers" },
      { feature: "School monitoring", purpose: "Review device and activity information within assigned school scope.", location: "Home → Monitoring" },
    ],
  };
  return { platform, accountRole: role, features: [...common, ...(byRole[role] ?? [])] };
}

export function resolveAiChildSelection(messages: ChatMessage[], children: Array<{ id: string; fullName: string }>) {
  const question = messages.filter(message => message.role === "user").slice(-6).map(message => message.content).join(" ")
    .normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();
  const normalized = (value: string) => value.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
  const query = ` ${normalized(question)} `;
  const named = children.filter(child => {
    const name = normalized(child.fullName);
    return name.length >= 2 && query.includes(` ${name} `);
  });
  if (named.length === 1) return { childIds: [named[0].id], needsClarification: false, choices: [] as string[] };
  if (named.length > 1) return { childIds: named.map(child => child.id), needsClarification: false, choices: [] as string[] };
  const firstNameMatches = children.filter(child => {
    const firstName = normalized(child.fullName).split(" ")[0];
    return firstName.length >= 2 && query.includes(` ${firstName} `);
  });
  if (firstNameMatches.length === 1) return { childIds: [firstNameMatches[0].id], needsClarification: false, choices: [] as string[] };
  if (firstNameMatches.length > 1) return { childIds: [], needsClarification: true, choices: firstNameMatches.slice(0, 10).map(child => cleanContextText(child.fullName, 80) ?? "Mtoto") };
  const allChildren = /\b(all (my )?(children|kids)|both (my )?(children|kids)|my children|my kids|children|kids|watoto|children wangu|watoto wangu( wote)?|kila mtoto|each child|every child)\b/.test(question);
  if (allChildren || children.length <= 1) return { childIds: children.map(child => child.id), needsClarification: false, choices: [] as string[] };
  const singularChild = /\b(my child|my son|my daughter|child wangu|mtoto wangu|huyo mtoto|yule mtoto|mtoto huyu|mtoto wake|child|son|daughter|mtoto|mwanafunzi|student)\b/.test(question);
  const individualDataQuestion = /\b(screen.?time|usage|apps?|application|activity|activities|device|phone|tablet|location|where|muda wa simu|matumizi|programu|shughuli|kifaa|simu|mahali|wapi)\b/.test(question);
  if (singularChild || individualDataQuestion) return { childIds: [] as string[], needsClarification: true, choices: children.slice(0, 10).map(child => cleanContextText(child.fullName, 80) ?? "Mtoto") };
  return { childIds: children.map(child => child.id), needsClarification: false, choices: [] as string[] };
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
