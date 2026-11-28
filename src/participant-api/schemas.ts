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
    signals: { type: "array", items: { enum: [...SIGNALS] }, minItems: 1, maxItems: 8, uniqueItems: true },
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

// ---- second-wave signals ----
/** Calendar date, validated semantically in {@link checkSecondWave}; the pattern only bounds the shape. */
const DATE = { type: "string", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}$", maxLength: 10 } as const;
const BASE = { phoneNumber: PHONE, purposeCode: { enum: [...PURPOSES] }, consentRef: CONSENT_REF } as const;
export const MAX_RECYCLING_LOOKBACK_DAYS = 1826, MAX_TENURE_DAYS = 3650;
export const MIN_RADIUS_M = 2000, MAX_RADIUS_M = 200000, MIN_LOCATION_AGE_S = 60, MAX_LOCATION_AGE_S = 3600;
export const SCHEMA_NUMBER_RECYCLING = { type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef", "specifiedDate"], properties: { ...BASE, specifiedDate: DATE } } as const;
export const SCHEMA_KYC_TENURE = { type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef", "minTenureDays"], properties: { ...BASE, minTenureDays: { type: "integer", minimum: 1, maximum: MAX_TENURE_DAYS } } } as const;
export const SCHEMA_DEVICE_LOCATION = {
  type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef", "latitude", "longitude", "radiusMeters"],
  properties: { ...BASE, latitude: { type: "number", minimum: -90, maximum: 90 }, longitude: { type: "number", minimum: -180, maximum: 180 },
    radiusMeters: { type: "number", minimum: MIN_RADIUS_M, maximum: MAX_RADIUS_M }, maxAgeSeconds: { type: "integer", minimum: MIN_LOCATION_AGE_S, maximum: MAX_LOCATION_AGE_S } },
} as const;
export const SCHEMA_DEVICE_ROAMING = { type: "object", additionalProperties: false, required: ["phoneNumber", "purposeCode", "consentRef"], properties: { ...BASE } } as const;
export const validateNumberRecycling = ajv.compile(SCHEMA_NUMBER_RECYCLING);
export const validateKycTenure = ajv.compile(SCHEMA_KYC_TENURE);
export const validateDeviceLocation = ajv.compile(SCHEMA_DEVICE_LOCATION);
export const validateDeviceRoaming = ajv.compile(SCHEMA_DEVICE_ROAMING);

/** Real calendar date (no 2026-02-31), not in the future, not older than `maxDays`. */
export function validPastDate(s: string, maxDays: number, now = Date.now()): boolean {
  const t = Date.parse(`${s}T00:00:00Z`);
  if (Number.isNaN(t) || new Date(t).toISOString().slice(0, 10) !== s) return false;
  return t <= now && t >= now - maxDays * 864e5;
}
