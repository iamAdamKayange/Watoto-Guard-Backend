import assert from "node:assert/strict";
import test from "node:test";
import { sendSendlibOtpEmail } from "../src/sendlib";

const accepted = () => new Response(JSON.stringify({ success: true }), { status: 200 });

test("registration OTP uses Sendlib's documented OTP template request", async () => {
  let requestUrl = "";
  let requestInit: RequestInit | undefined;
  await sendSendlibOtpEmail({
    apiKey: "test-key",
    email: "new-user@example.com",
    code: "012345",
    name: "New User",
    fetchImpl: async (input, init) => {
      requestUrl = String(input);
      requestInit = init;
      return accepted();
    },
  });
  assert.equal(requestUrl, "https://sendlib.samueltuoyo.com/api/send");
  assert.equal(requestInit?.method, "POST");
  assert.equal(new Headers(requestInit?.headers).get("authorization"), "Bearer test-key");
  assert.equal(new Headers(requestInit?.headers).get("content-type"), "application/json");
  assert.deepEqual(JSON.parse(String(requestInit?.body)), {
    template: "otp",
    to: "new-user@example.com",
    data: { code: "012345", name: "New User" },
  });
});

test("change-email OTP uses the same Sendlib OTP template with the recipient's name", async () => {
  let payload: Record<string, unknown> | undefined;
  await sendSendlibOtpEmail({
    apiKey: "test-key",
    email: "replacement@example.com",
    code: "654321",
    name: "Parent Name",
    fetchImpl: async (_input, init) => {
      payload = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return accepted();
    },
  });
  assert.deepEqual(payload, {
    template: "otp",
    to: "replacement@example.com",
    data: { code: "654321", name: "Parent Name" },
  });
});

test("provider rejections fail closed for unauthorized, rate limited, and server errors", async () => {
  for (const status of [401, 429, 500]) {
    await assert.rejects(
      sendSendlibOtpEmail({
        apiKey: "test-key",
        email: "person@example.com",
        code: "123456",
        name: "User",
        fetchImpl: async () => new Response("provider details", { status }),
      }),
      { message: "Verification email could not be sent" },
    );
  }
});

test("network and timeout failures are propagated without exposing message contents", async () => {
  await assert.rejects(
    sendSendlibOtpEmail({
      apiKey: "test-key",
      email: "person@example.com",
      code: "123456",
      name: "User",
      fetchImpl: async () => { throw new Error("network unavailable"); },
    }),
    { message: "network unavailable" },
  );
});
