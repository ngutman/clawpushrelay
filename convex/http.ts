import { anyApi, httpActionGeneric, httpRouter } from "convex/server";
import { loadRelayConfig } from "./relay/config.js";
import {
  handleChallengeRequest,
  handleHealthzRequest,
  handleRegisterRequest,
  handleSendRequest,
} from "./relay/http.js";

const http = httpRouter();

http.route({
  path: "/healthz",
  method: "GET",
  handler: httpActionGeneric(async () => handleHealthzRequest()),
});

http.route({
  path: "/v1/push/challenge",
  method: "POST",
  handler: httpActionGeneric(async (ctx, request) => {
    const config = loadRelayConfig();
    return handleChallengeRequest({
      request,
      config,
      issueChallenge: (args) =>
        ctx.runMutation(anyApi.relay.internal.issueChallengeAndConsumeRateLimitInternal, args),
    });
  }),
});

http.route({
  path: "/v1/push/register",
  method: "POST",
  handler: httpActionGeneric(async (ctx, request) => {
    const config = loadRelayConfig();
    return handleRegisterRequest({
      request,
      config,
      consumeChallengeAndRegisterRateLimit: (args) =>
        ctx.runMutation(anyApi.relay.internal.consumeChallengeAndRegisterRateLimitInternal, args),
      register: (args) =>
        ctx.runAction(anyApi.relay.registerNode.verifyAndPersistRegistrationInternal, args),
    });
  }),
});

http.route({
  path: "/v1/push/send",
  method: "POST",
  handler: httpActionGeneric(async (ctx, request) => {
    const config = loadRelayConfig();
    return handleSendRequest({
      request,
      config,
      consumeSendRateLimit: (args) =>
        ctx.runMutation(anyApi.relay.internal.consumeSendRateLimitInternal, args),
      send: (args) => ctx.runAction(anyApi.relay.sendNode.sendPushInternal, args),
    });
  }),
});

export default http;
