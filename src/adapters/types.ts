import type { Signal } from "../consent/consent.js";
export type SignalStatus = "TRUE" | "FALSE" | "UNAVAILABLE" | "NOT_SUPPORTED";
export type FieldMatch = "MATCH" | "NO_MATCH" | "NOT_AVAILABLE";
/** KYC attributes: processed in memory only, NEVER stored, logged, audited or metered. */
export type KycInput = Partial<Record<"idDocument" | "name" | "givenName" | "familyName" | "address" | "birthdate" | "email" | "postalCode" | "country", string>>;
export interface AdapterRequest { signal: Signal; msisdn: string; maxAgeHours?: number; kyc?: KycInput; correlationId: string }
export interface AdapterResult { status: SignalStatus; telcoMs: number; reason: string; fields?: Record<string, FieldMatch> }
/** Adapters NEVER throw and NEVER return FALSE/TRUE unless the telco gave a well-formed, explicit, schema-valid answer. */
export interface TelcoAdapter { readonly telcoId: string; readonly supports: ReadonlySet<Signal>; call(r: AdapterRequest): Promise<AdapterResult>; close(): Promise<void> }
