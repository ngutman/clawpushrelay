import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";
import { apnsTokenSuffix, decryptString, encryptString, hashSha256 } from "./crypto.js";
import type {
  AppAttestRecord,
  RelayRegistrationRecord,
  RelayState,
  RegistrationStatus,
} from "./types.js";

const STATE_FILE_NAME = "relay-state.json";

const EMPTY_STATE: RelayState = {
  version: 1,
  appAttestKeysById: {},
  registrationsByHandleHash: {},
};

export class RelayStateStore {
  private readonly stateFilePath: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(
    stateDir: string,
    private readonly encryptionKey: Buffer,
  ) {
    this.stateFilePath = path.join(stateDir, STATE_FILE_NAME);
  }

  async ensureReady(): Promise<void> {
    await fs.mkdir(path.dirname(this.stateFilePath), { recursive: true });
  }

  async loadState(): Promise<RelayState> {
    await this.ensureReady();
    try {
      const raw = await fs.readFile(this.stateFilePath, "utf8");
      const parsed = JSON.parse(raw) as RelayState;
      return {
        version: 1,
        appAttestKeysById: parsed.appAttestKeysById ?? {},
        registrationsByHandleHash: parsed.registrationsByHandleHash ?? {},
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return structuredClone(EMPTY_STATE);
      }
      throw error;
    }
  }

  async saveState(state: RelayState): Promise<void> {
    await this.ensureReady();
    const tempPath = `${this.stateFilePath}.${randomUUID()}.tmp`;
    await fs.writeFile(tempPath, JSON.stringify(state, null, 2), "utf8");
    await fs.rename(tempPath, this.stateFilePath);
  }

  async getAppAttestRecord(keyId: string): Promise<AppAttestRecord | null> {
    const state = await this.loadState();
    return state.appAttestKeysById[keyId] ?? null;
  }

  async upsertAppAttestRecord(record: AppAttestRecord): Promise<void> {
    await this.withWriteLock(async () => {
      const state = await this.loadState();
      state.appAttestKeysById[record.keyId] = record;
      await this.saveState(state);
    });
  }

  async replaceRegistration(params: {
    installationId: string;
    bundleId: string;
    environment: RelayRegistrationRecord["environment"];
    distribution: RelayRegistrationRecord["distribution"];
    relayHandle: string;
    relayHandleExpiresAtMs: number;
    apnsTopic: string;
    apnsToken: string;
    appAttestKeyId: string;
    receiptEnvironment: string;
    appVersion: string;
    nowMs: number;
  }): Promise<RelayRegistrationRecord> {
    return await this.withWriteLock(async () => {
      const state = await this.loadState();
      for (const record of Object.values(state.registrationsByHandleHash)) {
        if (
          record.installationId === params.installationId &&
          record.bundleId === params.bundleId &&
          record.environment === params.environment &&
          record.status === "active"
        ) {
          record.status = "stale";
          record.updatedAtMs = params.nowMs;
        }
      }

      const registration: RelayRegistrationRecord = {
        registrationId: randomUUID(),
        installationId: params.installationId,
        bundleId: params.bundleId,
        environment: params.environment,
        distribution: params.distribution,
        apnsTopic: params.apnsTopic,
        apnsTokenCiphertext: encryptString(params.apnsToken, this.encryptionKey),
        apnsTokenHash: this.hashApnsToken(params.apnsToken),
        tokenSuffix: apnsTokenSuffix(params.apnsToken),
        relayHandleHash: hashSha256(params.relayHandle),
        relayHandleExpiresAtMs: params.relayHandleExpiresAtMs,
        appAttestKeyId: params.appAttestKeyId,
        proofType: "receipt",
        receiptEnvironment: params.receiptEnvironment,
        appVersion: params.appVersion,
        status: "active",
        createdAtMs: params.nowMs,
        updatedAtMs: params.nowMs,
        lastRegisteredAtMs: params.nowMs,
      };
      state.registrationsByHandleHash[registration.relayHandleHash] = registration;
      await this.saveState(state);
      return registration;
    });
  }

  async findRegistrationByHandle(relayHandle: string): Promise<RelayRegistrationRecord | null> {
    const state = await this.loadState();
    return state.registrationsByHandleHash[hashSha256(relayHandle)] ?? null;
  }

  async decryptApnsToken(record: RelayRegistrationRecord): Promise<string> {
    return decryptString(record.apnsTokenCiphertext, this.encryptionKey);
  }

  async updateSendResult(params: {
    relayHandle: string;
    status: number;
    reason?: string;
    nowMs: number;
  }): Promise<RelayRegistrationRecord | null> {
    return await this.withWriteLock(async () => {
      const state = await this.loadState();
      const handleHash = hashSha256(params.relayHandle);
      const record = state.registrationsByHandleHash[handleHash];
      if (!record) {
        return null;
      }
      record.lastSentAtMs = params.nowMs;
      record.lastApnsStatus = params.status;
      record.lastApnsReason = params.reason;
      record.updatedAtMs = params.nowMs;
      if (params.status === 410 || (params.status === 400 && params.reason === "BadDeviceToken")) {
        record.status = "stale";
      }
      await this.saveState(state);
      return record;
    });
  }

  async markRegistrationStatus(
    relayHandle: string,
    status: RegistrationStatus,
    nowMs: number,
    reason?: string,
  ): Promise<RelayRegistrationRecord | null> {
    return await this.withWriteLock(async () => {
      const state = await this.loadState();
      const handleHash = hashSha256(relayHandle);
      const record = state.registrationsByHandleHash[handleHash];
      if (!record) {
        return null;
      }
      record.status = status;
      record.updatedAtMs = nowMs;
      if (reason) {
        record.lastApnsReason = reason;
      }
      await this.saveState(state);
      return record;
    });
  }

  private hashApnsToken(token: string): string {
    return createHash("sha256").update(token.trim().toLowerCase(), "utf8").digest("hex");
  }

  private async withWriteLock<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.writeChain.then(operation, operation);
    this.writeChain = next.then(
      () => undefined,
      () => undefined,
    );
    return await next;
  }
}
