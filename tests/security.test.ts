import assert from "node:assert/strict";
import { test } from "node:test";
import { scryptSync } from "node:crypto";
import { RateLimiter, TtlCache, hashPasswordAsync, runWithConcurrency, verifyPasswordAsync } from "../src/security";

test("async password hashes verify and reject wrong passwords", async () => {
  const encoded = await hashPasswordAsync("correct horse battery");
  assert.equal(await verifyPasswordAsync("correct horse battery", encoded), true);
  assert.equal(await verifyPasswordAsync("wrong password", encoded), false);
  assert.equal(await verifyPasswordAsync("x", "malformed"), false);
});

test("async verification accepts hashes created by the previous sync implementation", async () => {
  const salt = "c2FsdHNhbHRzYWx0";
  const legacy = `${salt}:${scryptSync("legacy-password", salt, 64).toString("base64url")}`;
  assert.equal(await verifyPasswordAsync("legacy-password", legacy), true);
});

test("rate limiter blocks after the limit and reports a retry delay", () => {
  const limiter = new RateLimiter();
  try {
    assert.equal(limiter.hit("k", 2, 60_000), 0);
    assert.equal(limiter.hit("k", 2, 60_000), 0);
    assert.ok(limiter.hit("k", 2, 60_000) > 0);
    assert.equal(limiter.hit("other", 2, 60_000), 0);
    limiter.reset("k");
    assert.equal(limiter.hit("k", 2, 60_000), 0);
  } finally { limiter.stop(); }
});

test("concurrency runner processes every item and never exceeds the bound", async () => {
  let active = 0, peak = 0;
  const done: number[] = [];
  await runWithConcurrency([1, 2, 3, 4, 5, 6, 7], 3, async item => {
    active++; peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 5));
    done.push(item); active--;
  });
  assert.equal(done.length, 7);
  assert.ok(peak <= 3);
});

test("ttl cache expires entries", async () => {
  const cache = new TtlCache<number>(10);
  cache.set("a", 1);
  assert.equal(cache.get("a"), 1);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(cache.get("a"), undefined);
});
