export async function sendSendlibOtpEmail(options: {
  apiKey: string;
  from?: string;
  email: string;
  code: string;
  name: string;
  fetchImpl?: typeof fetch;
}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl("https://sendlib.samueltuoyo.com/api/send", {
    method: "POST",
    signal: AbortSignal.timeout(10_000),
    headers: {
      Authorization: `Bearer ${options.apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      ...(options.from?.trim() ? { from: options.from.trim() } : {}),
      template: "otp",
      to: options.email,
      data: { code: options.code, name: options.name },
    }),
  });

  if (!response.ok) {
    console.error("SendLib email request rejected", response.status);
    throw new Error("Verification email could not be sent");
  }
}

export async function sendSendlibEmail(options: {
  apiKey: string;
  from?: string;
  to: string;
  subject: string;
  html: string;
  text: string;
  fetchImpl?: typeof fetch;
}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl("https://sendlib.samueltuoyo.com/api/send", {
    method: "POST",
    signal: AbortSignal.timeout(10_000),
    headers: {
      Authorization: `Bearer ${options.apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      ...(options.from?.trim() ? { from: options.from.trim() } : {}),
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text,
    }),
  });

  if (!response.ok) {
    console.error("SendLib transactional email request rejected", response.status);
    throw new Error("Transactional email could not be sent");
  }
}
