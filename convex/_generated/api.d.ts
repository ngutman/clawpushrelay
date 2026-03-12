/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as crons from "../crons.js";
import type * as http from "../http.js";
import type * as relay_cleanup from "../relay/cleanup.js";
import type * as relay_config from "../relay/config.js";
import type * as relay_gatewayAuth from "../relay/gatewayAuth.js";
import type * as relay_hashes from "../relay/hashes.js";
import type * as relay_http from "../relay/http.js";
import type * as relay_internal from "../relay/internal.js";
import type * as relay_nodeCrypto from "../relay/nodeCrypto.js";
import type * as relay_registerNode from "../relay/registerNode.js";
import type * as relay_sendNode from "../relay/sendNode.js";
import type * as relay_types from "../relay/types.js";
import type * as relay_validators from "../relay/validators.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  crons: typeof crons;
  http: typeof http;
  "relay/cleanup": typeof relay_cleanup;
  "relay/config": typeof relay_config;
  "relay/gatewayAuth": typeof relay_gatewayAuth;
  "relay/hashes": typeof relay_hashes;
  "relay/http": typeof relay_http;
  "relay/internal": typeof relay_internal;
  "relay/nodeCrypto": typeof relay_nodeCrypto;
  "relay/registerNode": typeof relay_registerNode;
  "relay/sendNode": typeof relay_sendNode;
  "relay/types": typeof relay_types;
  "relay/validators": typeof relay_validators;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
