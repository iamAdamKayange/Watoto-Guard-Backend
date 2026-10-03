export async function sendSendlibOtpEmail(options: {
  apiKey: string;
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
