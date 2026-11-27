import { Ajv } from "ajv";
import { PURPOSES, SIGNALS } from "../consent/consent.js";
const ajv = new Ajv({ strict: true, allErrors: false, removeAdditional: false, useDefaults: false, coerceTypes: false });
const PHONE = { type: "string", pattern: "^\\+[1-9][0-9]{4,14}$", maxLength: 16 } as const;
const CONSENT_REF = { type: "string", pattern: "^[A-Za-z0-9._:-]{4,128}$" } as const;

export const SCHEMA_SIM_SWAP = {
  type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef"],
  properties: { phoneNumber: PHONE, maxAge: { type: "integer", minimum: 1, maximum: 2400 }, purposeCode: { enum: [...PURPOSES] }, consentRef: CONSENT_REF },
} as const;
export const SCHEMA_CREATE_CONSENT = {
  type: "object", additionalProperties: false, required: ["phoneNumber", "consentRef", "purposeCode", "signals", "expiresAt"],
  properties: {
    phoneNumber: PHONE, consentRef: CONSENT_REF, purposeCode: { enum: [...PURPOSES] },
    signals: { type: "array", items: { enum: [...SIGNALS] }, minItems: 1, maxItems: 4, uniqueItems: true },
    expiresAt: { type: "string", maxLength: 40 },
  },
} as const;
export const validateSimSwapCheck = ajv.compile(SCHEMA_SIM_SWAP);
export const validateCreateConsent = ajv.compile(SCHEMA_CREATE_CONSENT);
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const validateDeviceSwapCheck = validateSimSwapCheck;
export const SCHEMA_CALL_FORWARDING = {
  type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef"],
  properties: { phoneNumber: PHONE, purposeCode: { enum: [...PURPOSES] }, consentRef: CONSENT_REF },
} as const;
export const validateCallForwardingCheck = ajv.compile(SCHEMA_CALL_FORWARDING);
const KYC_STR = { type: "string", minLength: 1, maxLength: 256 } as const;
const KYC_FIELDS = ["idDocument", "name", "givenName", "familyName", "address", "birthdate", "email", "postalCode", "country"] as const;
export const SCHEMA_KYC_MATCH = {
  type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef"],
  properties: { phoneNumber: PHONE, purposeCode: { enum: [...PURPOSES] }, consentRef: CONSENT_REF, ...Object.fromEntries(KYC_FIELDS.map((f) => [f, KYC_STR])) },
  anyOf: KYC_FIELDS.map((f) => ({ required: [f], properties: { [f]: KYC_STR } })),     // at least one attribute to match
} as const;
export const validateKycMatch = ajv.compile(SCHEMA_KYC_MATCH);
export { KYC_FIELDS };
