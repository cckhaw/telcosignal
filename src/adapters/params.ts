import type { Signal } from "../consent/consent.js";
import type { KycInput, SignalParams } from "./types.js";

/** UTC calendar date `days` days before `now`, as YYYY-MM-DD. */
export function dateDaysAgo(days: number, now = Date.now()): string {
  return new Date(now - days * 864e5).toISOString().slice(0, 10);
}
/** Synthetic parameters used by the telco conformance test and the admin test console (synthetic numbers only). */
export function syntheticParams(signal: Signal): { kyc?: KycInput; params?: SignalParams } {
  switch (signal) {
    case "KYC_MATCH": return { kyc: { name: "Synthetic Person" } };
    case "NUMBER_RECYCLING": return { params: { specifiedDate: dateDaysAgo(30) } };
    case "KYC_TENURE": return { params: { minTenureDays: 90 } };
    case "DEVICE_LOCATION": return { params: { area: { latitude: 3.139, longitude: 101.6869, radiusMeters: 5000 }, maxAgeSeconds: 600 } };
    default: return {};
  }
}
/** The mock telcos answer a positive for a trailing 1 and a negative for a trailing 0, except KYC match which is inverted (a match is the 'good' answer). */
export const conformanceDigits = (signal: Signal): { positive: string; negative: string } => signal === "KYC_MATCH" ? { positive: "0", negative: "1" } : { positive: "1", negative: "0" };
