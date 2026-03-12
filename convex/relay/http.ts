import { ZodError } from "zod";
import type { RelayConfig } from "./config.js";
import { hashSha256 } from "./hashes.js";
import { parseRegisterRequest, parseSendRequest, validatePushPayload } from "./validators.js";
import type {
  ChallengeRecord,
  RegisterActionResult,
  RelaySendResult,
  SendRequestBody,
} from "./types.js";

type UnauthorizedSendResult = {
  unauthorized: true;
  message: string;
};

export type ChallengeRouteConfig = Pick<
  RelayConfig,
  "challengeTtlMs" | "rateLimitWindowMs" | "challengeRateLimitMax"
>;

export type RegisterRouteConfig = Pick<
  RelayConfig,
  "allowedBundleIds" | "rateLimitWindowMs" | "registerRateLimitMax"
>;

export type SendRouteConfig = Pick<
  RelayConfig,
  "rateLimitWindowMs" | "sendRateLimitMax"
>;

export type IssueChallengeArgs = {
  challengeId: string;
  challenge: string;
  subjectHash: string;
  nowMs: number;
  ttlMs: number;
  windowMs: number;
  limit: number;
};

export type IssueChallengeResult = {
  allowed: boolean;
  remaining: number;
  challenge: ChallengeRecord | null;
};

export type ConsumeChallengeAndRegisterRateLimitArgs = {
  challengeId: string;
  subjectHash: string;
  nowMs: number;
  windowMs: number;
  limit: number;
};

export type ConsumeChallengeAndRegisterRateLimitResult = {
  allowed: boolean;
  remaining: number;
  challenge: ChallengeRecord | null;
};

export type ConsumeSendRateLimitArgs = {
  subjectHash: string;
  nowMs: number;
  windowMs: number;
  limit: number;
};

export type ConsumeSendRateLimitResult = {
  allowed: boolean;
  remaining: number;
};

function jsonResponse(body: unknown, init: ResponseInit): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json");
  return new Response(JSON.stringify(body), {
    ...init,
    headers,
  });
}

function clientIp(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for")?.trim();
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() || "unknown";
  }
  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp) {
    return realIp;
  }
  const cfConnectingIp = headers.get("cf-connecting-ip")?.trim();
  if (cfConnectingIp) {
    return cfConnectingIp;
  }
  return "unknown";
}

function toBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomOpaqueToken(bytes: number): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function issueChallengeSeed(): Pick<ChallengeRecord, "challengeId" | "challenge"> {
  return {
    challengeId: crypto.randomUUID(),
    challenge: randomOpaqueToken(32),
  };
}

export async function handleHealthzRequest(): Promise<Response> {
  return jsonResponse(
    { ok: true },
    {
      status: 200,
    },
  );
}

function noStoreJsonResponse(body: unknown, init: ResponseInit): Response {
  const headers = new Headers(init.headers);
  headers.set("cache-control", "no-store");
  return jsonResponse(body, {
    ...init,
    headers,
  });
}

function invalidRequest(message: string): Response {
  return jsonResponse(
    {
      error: "invalid_request",
      message,
    },
    {
      status: 400,
    },
  );
}

function rateLimited(): Response {
  return jsonResponse(
    {
      error: "rate_limited",
      message: "rate limit exceeded",
    },
    {
      status: 429,
    },
  );
}

function bundleNotAllowed(): Response {
  return jsonResponse(
    {
      error: "bundle_not_allowed",
      message: "bundle id is not allowed",
    },
    {
      status: 403,
    },
  );
}

function invalidChallenge(): Response {
  return noStoreJsonResponse(
    {
      error: "invalid_challenge",
      message: "challenge missing or expired",
    },
    {
      status: 401,
    },
  );
}

function noStoreUnauthorized(message: string): Response {
  return noStoreJsonResponse(
    {
      error: "unauthorized",
      message,
    },
    {
      status: 401,
    },
  );
}

function noStoreServiceUnavailable(message: string): Response {
  return noStoreJsonResponse(
    {
      error: "service_unavailable",
      message,
    },
    {
      status: 503,
    },
  );
}

function gatewayUnauthorized(message: string): Response {
  return jsonResponse(
    {
      error: "unauthorized",
      message,
    },
    {
      status: 401,
    },
  );
}

function parseBearerToken(authorizationHeader: string | null): string | null {
  const authorization = authorizationHeader?.trim() ?? "";
  if (!authorization) {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  const token = match?.[1]?.trim() ?? "";
  return token.length > 0 ? token : null;
}

function isUnauthorizedSendResult(
  value: RelaySendResult | UnauthorizedSendResult,
): value is UnauthorizedSendResult {
  return "unauthorized" in value && value.unauthorized === true;
}

export async function handleChallengeRequest(params: {
  request: Request;
  config: ChallengeRouteConfig;
  issueChallenge: (args: IssueChallengeArgs) => Promise<IssueChallengeResult>;
}): Promise<Response> {
  const nowMs = Date.now();
  const seed = issueChallengeSeed();
  const subjectHash = await hashSha256(clientIp(params.request.headers));
  const result = await params.issueChallenge({
    challengeId: seed.challengeId,
    challenge: seed.challenge,
    subjectHash,
    nowMs,
    ttlMs: params.config.challengeTtlMs,
    windowMs: params.config.rateLimitWindowMs,
    limit: params.config.challengeRateLimitMax,
  });

  if (!result.allowed || !result.challenge) {
    return rateLimited();
  }

  return jsonResponse(result.challenge, {
    status: 200,
    headers: {
      "cache-control": "no-store",
    },
  });
}

export async function handleRegisterRequest(params: {
  request: Request;
  config: RegisterRouteConfig;
  consumeChallengeAndRegisterRateLimit: (
    args: ConsumeChallengeAndRegisterRateLimitArgs,
  ) => Promise<ConsumeChallengeAndRegisterRateLimitResult>;
  register: (args: {
    challenge: string;
    request: ReturnType<typeof parseRegisterRequest>;
  }) => Promise<RegisterActionResult>;
}): Promise<Response> {
  let body: ReturnType<typeof parseRegisterRequest>;
  try {
    body = parseRegisterRequest(await params.request.json());
  } catch (error) {
    if (error instanceof ZodError) {
      return invalidRequest(error.issues[0]?.message ?? "invalid request");
    }
    return invalidRequest("invalid request");
  }

  if (!params.config.allowedBundleIds.includes(body.bundleId)) {
    return bundleNotAllowed();
  }

  const combined = await params.consumeChallengeAndRegisterRateLimit({
    challengeId: body.challengeId,
    subjectHash: await hashSha256(clientIp(params.request.headers)),
    nowMs: Date.now(),
    windowMs: params.config.rateLimitWindowMs,
    limit: params.config.registerRateLimitMax,
  });

  if (!combined.allowed) {
    return rateLimited();
  }

  if (!combined.challenge) {
    return invalidChallenge();
  }

  const result = await params.register({
    challenge: combined.challenge.challenge,
    request: body,
  });

  if (!result.ok) {
    if (result.error === "service_unavailable") {
      return noStoreServiceUnavailable(result.message);
    }
    return noStoreUnauthorized(result.message);
  }

  return noStoreJsonResponse(result.response, {
    status: 200,
  });
}

export async function handleSendRequest(params: {
  request: Request;
  config: SendRouteConfig;
  consumeSendRateLimit: (args: ConsumeSendRateLimitArgs) => Promise<ConsumeSendRateLimitResult>;
  send: (args: {
    request: SendRequestBody;
    sendGrant: string;
  }) => Promise<RelaySendResult | UnauthorizedSendResult>;
}): Promise<Response> {
  const subjectHash = await hashSha256(clientIp(params.request.headers));
  const rateLimit = await params.consumeSendRateLimit({
    subjectHash,
    nowMs: Date.now(),
    windowMs: params.config.rateLimitWindowMs,
    limit: params.config.sendRateLimitMax,
  });

  if (!rateLimit.allowed) {
    return rateLimited();
  }

  let body: SendRequestBody;
  try {
    body = parseSendRequest(await params.request.json());
  } catch (error) {
    if (error instanceof ZodError) {
      return invalidRequest(error.issues[0]?.message ?? "invalid request");
    }
    return invalidRequest("invalid request");
  }

  const payloadError = validatePushPayload(body);
  if (payloadError) {
    return invalidRequest(payloadError);
  }

  const sendGrant = parseBearerToken(params.request.headers.get("authorization"));
  if (!sendGrant) {
    return gatewayUnauthorized("missing or invalid relay send grant");
  }

  const result = await params.send({
    request: body,
    sendGrant,
  });
  if (isUnauthorizedSendResult(result)) {
    return gatewayUnauthorized(result.message);
  }
  return jsonResponse(result, {
    status: result.status,
  });
}
