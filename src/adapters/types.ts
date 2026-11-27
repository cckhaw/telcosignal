import type { Signal } from "../consent/consent.js";
export type SignalStatus = "TRUE" | "FALSE" | "UNAVAILABLE" | "NOT_SUPPORTED";
export interface AdapterRequest { signal: Signal; msisdn: string; maxAgeHours?: number; correlationId: string }
export interface AdapterResult { status: SignalStatus; telcoMs: number; reason: string }
/** Adapters NEVER throw and NEVER return FALSE unless the telco gave a well-formed, explicit negative. */
export interface TelcoAdapter { readonly telcoId: string; readonly supports: ReadonlySet<Signal>; call(r: AdapterRequest): Promise<AdapterResult>; close(): Promise<void> }
