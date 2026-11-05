import type { NextFunction, Request, Response } from "express";
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const SCRYPT_KEY_LENGTH = 64;

function scryptAsync(password: string, salt: string, keyLength: number) {
  return new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, keyLength, (error, derived) => (error ? reject(error) : resolve(derived)));
  });
}

/** Hashes off the event loop so concurrent logins do not stall every other request. */
export async function hashPasswordAsync(password: string) {
  const salt = randomBytes(16).toString("base64url");
  return `${salt}:${(await scryptAsync(password, salt, SCRYPT_KEY_LENGTH)).toString("base64url")}`;
}

export async function verifyPasswordAsync(password: string, encoded: string) {
  const [salt, hash] = encoded.split(":");
  if (!salt || !hash) return false;
  const expected = Buffer.from(hash, "base64url");
  if (!expected.length) return false;
  const actual = await scryptAsync(password, salt, expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// Used when an account does not exist, so response timing does not reveal registered emails.
let dummyHash: Promise<string> | null = null;
export async function burnPasswordCheck(password: string) {
  dummyHash ??= hashPasswordAsync(randomBytes(18).toString("base64url"));
  await verifyPasswordAsync(password, await dummyHash);
}

type Bucket = { count: number; resetAt: number };

/**
 * Small fixed-window limiter for a single API instance. It needs no Redis and is
 * suitable for the single-node Hetzner deployment; counters reset on restart.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly sweep: NodeJS.Timeout;

  constructor(private readonly maxEntries = 100_000) {
    this.sweep = setInterval(() => this.prune(), 60_000);
    this.sweep.unref();
  }

  /** Returns seconds to wait when the limit is exceeded, otherwise 0. */
  hit(key: string, limit: number, windowMs: number) {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      if (this.buckets.size >= this.maxEntries) this.prune();
      bucket = { count: 0, resetAt: now + windowMs };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    return bucket.count > limit ? Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)) : 0;
  }

  reset(key: string) { this.buckets.delete(key); }

  private prune() {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) if (bucket.resetAt <= now) this.buckets.delete(key);
  }

  stop() { clearInterval(this.sweep); }
}

export const limiter = new RateLimiter();

export function clientIp(req: Request) {
  return req.ip || req.socket.remoteAddress || "unknown";
}

export function tooMany(res: Response, retryAfterSeconds: number) {
  res.setHeader("Retry-After", String(retryAfterSeconds));
  res.status(429).json({ error: "Too many requests. Please wait and try again.", code: "rate_limited", retryAfterSeconds });
}

/** Express middleware limiting a route per client IP. */
export function rateLimit(name: string, limit: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const wait = limiter.hit(`${name}:ip:${clientIp(req)}`, limit, windowMs);
    if (wait) { tooMany(res, wait); return; }
    next();
  };
}

/** Runs async work with bounded concurrency so large broadcasts don't exhaust the DB pool. */
export async function runWithConcurrency<T>(items: readonly T[], concurrency: number, worker: (item: T) => Promise<unknown>) {
  let index = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (index < items.length) {
      const item = items[index++];
      try { await worker(item); } catch (error) { console.error("Background task failed", error instanceof Error ? error.message : error); }
    }
  });
  await Promise.all(runners);
}

/** Short-lived in-process cache, used to avoid re-reading the same user on every request burst. */
export class TtlCache<V> {
  private readonly entries = new Map<string, { value: V; expiresAt: number }>();
  constructor(private readonly ttlMs: number, private readonly maxEntries = 10_000) {}
  get(key: string) {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) { this.entries.delete(key); return undefined; }
    return entry.value;
  }
  set(key: string, value: V) {
    if (this.entries.size >= this.maxEntries) this.entries.clear();
    this.entries.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }
  delete(key: string) { this.entries.delete(key); }
  clear() { this.entries.clear(); }
}
