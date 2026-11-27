// Error catalogue. Responses reveal no internals and never whether a number exists.
export const ERRORS = {
  INVALID_REQUEST: { status: 400, title: "Invalid request" },
  AUTHENTICATION_FAILED: { status: 401, title: "Authentication failed" },
  ACCESS_DENIED: { status: 403, title: "Access denied" },
  CONSENT_REQUIRED: { status: 403, title: "Consent or lawful basis not valid for this request" },
  REPLAY_REJECTED: { status: 401, title: "Request rejected" },
  RATE_LIMITED: { status: 429, title: "Too many requests" },
  PAYLOAD_TOO_LARGE: { status: 413, title: "Payload too large" },
  NOT_FOUND: { status: 404, title: "Not found" },
  INTERNAL: { status: 500, title: "Internal error" },
  SERVICE_UNAVAILABLE: { status: 503, title: "Service unavailable" },
} as const;
export type ErrorCode = keyof typeof ERRORS;

export class ApiError extends Error {
  constructor(
    public readonly code: ErrorCode,
    public readonly reason: string = code, // internal reason: audit/security log only, never returned
  ) {
    super(reason);
  }
}

export function problem(code: ErrorCode, correlationId: string) {
  const e = ERRORS[code];
  return { status: e.status, code, message: e.title, correlationId };
}
