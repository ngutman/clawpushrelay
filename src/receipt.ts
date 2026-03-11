import type { ReceiptVerificationResult } from "./types.js";

const APPLE_PRODUCTION_RECEIPT_URL = "https://buy.itunes.apple.com/verifyReceipt";
const APPLE_SANDBOX_RECEIPT_URL = "https://sandbox.itunes.apple.com/verifyReceipt";

type AppleVerifyReceiptResponse = {
  status: number;
  environment?: string;
  receipt?: {
    bundle_id?: string;
  };
};

export class ReceiptVerificationError extends Error {}
export class ReceiptVerificationServiceError extends Error {}

export class ReceiptVerifier {
  constructor(
    private readonly options: {
      sharedSecret?: string;
    },
    private readonly now: () => number = () => Date.now(),
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async verifyReceipt(params: {
    receiptBase64: string;
    bundleId: string;
  }): Promise<ReceiptVerificationResult> {
    const production = await this.callApple(APPLE_PRODUCTION_RECEIPT_URL, params.receiptBase64);
    const result =
      production.status === 21007
        ? await this.callApple(APPLE_SANDBOX_RECEIPT_URL, params.receiptBase64)
        : production;

    if (result.status !== 0) {
      throw new ReceiptVerificationError(`Apple receipt validation failed with status ${result.status}`);
    }
    const receiptBundleId = result.receipt?.bundle_id?.trim();
    if (!receiptBundleId || receiptBundleId !== params.bundleId) {
      throw new ReceiptVerificationError("receipt bundle id mismatch");
    }
    return {
      environment: result.environment ?? "unknown",
      bundleId: receiptBundleId,
      validatedAtMs: this.now(),
    };
  }

  private async callApple(
    url: string,
    receiptBase64: string,
  ): Promise<AppleVerifyReceiptResponse> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          "receipt-data": receiptBase64,
          ...(this.options.sharedSecret ? { password: this.options.sharedSecret } : {}),
          "exclude-old-transactions": true,
        }),
      });
    } catch (error) {
      throw new ReceiptVerificationServiceError(
        `Apple receipt validation unavailable: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!response.ok) {
      throw new ReceiptVerificationServiceError(
        `Apple receipt validation unavailable (HTTP ${response.status})`,
      );
    }
    return (await response.json()) as AppleVerifyReceiptResponse;
  }
}
