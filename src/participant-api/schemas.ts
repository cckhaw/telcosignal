import { Ajv } from "ajv";
import { PURPOSES, SIGNALS } from "../consent/consent.js";
const ajv = new Ajv({ strict: true, allErrors: false, removeAdditional: false, useDefaults: false, coerceTypes: false });
const PHONE = { type: "string", pattern: "^\\+[1-9][0-9]{4,14}$", maxLength: 16 } as const;
const CONSENT_REF = { type: "string", pattern: "^[A-Za-z0-9._:-]{4,128}$" } as const;

export const validateSimSwapCheck = ajv.compile({
  type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef"],
  properties: { phoneNumber: PHONE, maxAge: { type: "integer", minimum: 1, maximum: 2400 }, purposeCode: { enum: [...PURPOSES] }, consentRef: CONSENT_REF },
});
export const validateCreateConsent = ajv.compile({
  type: "object", additionalProperties: false, required: ["phoneNumber", "consentRef", "purposeCode", "signals", "expiresAt"],
  properties: {
    phoneNumber: PHONE, consentRef: CONSENT_REF, purposeCode: { enum: [...PURPOSES] },
    signals: { type: "array", items: { enum: [...SIGNALS] }, minItems: 1, maxItems: 4, uniqueItems: true },
    expiresAt: { type: "string", maxLength: 40 },
  },
});
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
