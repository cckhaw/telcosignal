import type { Signal } from "../consent/consent.js";
export type SignalStatus = "TRUE" | "FALSE" | "UNAVAILABLE" | "NOT_SUPPORTED";
export type FieldMatch = "MATCH" | "NO_MATCH" | "NOT_AVAILABLE";
/** KYC attributes: processed in memory only, NEVER stored, logged, audited or metered. */
export type KycInput = Partial<Record<"idDocument" | "name" | "givenName" | "familyName" | "address" | "birthdate" | "email" | "postalCode" | "country", string>>;
/** Per-signal parameters of the second-wave signals. Location values are sensitive: in memory only, NEVER stored, logged, audited or metered. */
export interface SignalParams {
  specifiedDate?: string;                                                       // NUMBER_RECYCLING, YYYY-MM-DD (UTC)
  minTenureDays?: number;                                                       // KYC_TENURE
  area?: { latitude: number; longitude: number; radiusMeters: number };        // DEVICE_LOCATION (circle)
  maxAgeSeconds?: number;                                                       // DEVICE_LOCATION freshness
}
export interface AdapterRequest { signal: Signal; msisdn: string; maxAgeHours?: number; kyc?: KycInput; params?: SignalParams; correlationId: string }
export interface AdapterResult { status: SignalStatus; telcoMs: number; reason: string; fields?: Record<string, FieldMatch> }
/** Adapters NEVER throw and NEVER return FALSE/TRUE unless the telco gave a well-formed, explicit, schema-valid answer. */
export interface TelcoAdapter { readonly telcoId: string; readonly supports: ReadonlySet<Signal>; call(r: AdapterRequest): Promise<AdapterResult>; close(): Promise<void> }
