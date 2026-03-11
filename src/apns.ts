import { createHash, createPrivateKey, sign as signJwt } from "node:crypto";
import http2 from "node:http2";
import type { RelaySendResult, PushType } from "./types.js";

type CachedJwt = {
  cacheKey: string;
  token: string;
  expiresAtMs: number;
};

export type ApnsSenderConfig = {
  teamId: string;
  keyId: string;
  privateKey: string;
};

export type ApnsSendParams = {
  token: string;
  topic: string;
  payload: Record<string, unknown>;
  pushType: PushType;
  priority: 5 | 10;
  timeoutMs?: number;
};

type ApnsRequestResponse = {
  status: number;
  apnsId?: string;
  body: string;
};

type ApnsRequestSender = (params: {
  token: string;
  topic: string;
  payload: Record<string, unknown>;
  bearerToken: string;
  pushType: PushType;
  priority: 5 | 10;
  timeoutMs: number;
}) => Promise<ApnsRequestResponse>;

const APNS_JWT_TTL_MS = 50 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 10_000;

let cachedJwt: CachedJwt | null = null;

function toBase64UrlBytes(value: Uint8Array): string {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function toBase64UrlJson(value: object): string {
  return toBase64UrlBytes(Buffer.from(JSON.stringify(value), "utf8"));
}

function getJwtCacheKey(config: ApnsSenderConfig): string {
  const keyHash = createHash("sha256").update(config.privateKey).digest("hex");
  return `${config.teamId}:${config.keyId}:${keyHash}`;
}

function getBearerToken(config: ApnsSenderConfig, nowMs: number = Date.now()): string {
  const cacheKey = getJwtCacheKey(config);
  if (cachedJwt && cachedJwt.cacheKey === cacheKey && nowMs < cachedJwt.expiresAtMs) {
    return cachedJwt.token;
  }
  const iat = Math.floor(nowMs / 1000);
  const header = toBase64UrlJson({ alg: "ES256", kid: config.keyId, typ: "JWT" });
  const payload = toBase64UrlJson({ iss: config.teamId, iat });
  const signingInput = `${header}.${payload}`;
  const signature = signJwt("sha256", Buffer.from(signingInput, "utf8"), {
    key: createPrivateKey(config.privateKey),
    dsaEncoding: "ieee-p1363",
  });
  const token = `${signingInput}.${toBase64UrlBytes(signature)}`;
  cachedJwt = {
    cacheKey,
    token,
    expiresAtMs: nowMs + APNS_JWT_TTL_MS,
  };
  return token;
}

function parseReason(body: string): string | undefined {
  const trimmed = body.trim();
  if (!trimmed) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(trimmed) as { reason?: unknown };
    return typeof parsed.reason === "string" && parsed.reason.trim() ? parsed.reason.trim() : trimmed;
  } catch {
    return trimmed;
  }
}

async function sendApnsRequest(params: {
  token: string;
  topic: string;
  payload: Record<string, unknown>;
  bearerToken: string;
  pushType: PushType;
  priority: 5 | 10;
  timeoutMs: number;
}): Promise<ApnsRequestResponse> {
  const body = JSON.stringify(params.payload);
  return await new Promise((resolve, reject) => {
    const client = http2.connect("https://api.push.apple.com");
    let settled = false;

    const fail = (error: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      client.destroy();
      reject(error);
    };

    const finish = (result: ApnsRequestResponse) => {
      if (settled) {
        return;
      }
      settled = true;
      client.close();
      resolve(result);
    };

    client.once("error", fail);
    const request = client.request({
      ":method": "POST",
      ":path": `/3/device/${params.token}`,
      authorization: `bearer ${params.bearerToken}`,
      "apns-topic": params.topic,
      "apns-push-type": params.pushType,
      "apns-priority": String(params.priority),
      "apns-expiration": "0",
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(body)),
    });

    let statusCode = 0;
    let apnsId: string | undefined;
    let responseBody = "";

    request.setEncoding("utf8");
    request.setTimeout(params.timeoutMs, () => {
      request.close(http2.constants.NGHTTP2_CANCEL);
      fail(new Error(`APNs request timed out after ${params.timeoutMs}ms`));
    });
    request.on("response", (headers) => {
      statusCode = Number(headers[":status"] ?? 0);
      const header = headers["apns-id"];
      if (typeof header === "string" && header.trim()) {
        apnsId = header.trim();
      }
    });
    request.on("data", (chunk) => {
      responseBody += String(chunk);
    });
    request.on("end", () => {
      finish({ status: statusCode, apnsId, body: responseBody });
    });
    request.on("error", fail);
    request.end(body);
  });
}

export class ApnsSender {
  constructor(
    private readonly config: ApnsSenderConfig,
    private readonly requestSender: ApnsRequestSender = sendApnsRequest,
  ) {}

  async send(params: ApnsSendParams): Promise<RelaySendResult> {
    const response = await this.requestSender({
      token: params.token.trim().replace(/[<>\s]/g, "").toLowerCase(),
      topic: params.topic.trim(),
      payload: params.payload,
      bearerToken: getBearerToken(this.config),
      pushType: params.pushType,
      priority: params.priority,
      timeoutMs: params.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
    return {
      ok: response.status === 200,
      status: response.status,
      apnsId: response.apnsId,
      reason: parseReason(response.body),
      environment: "production",
      tokenSuffix: params.token.slice(-8).toLowerCase(),
    };
  }
}
