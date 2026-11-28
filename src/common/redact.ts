// Central redaction: no raw phone numbers or identity attributes in logs, traces, metrics.
const E164 = /\+[1-9][0-9]{4,14}/g;
export function maskText(s: string): string {
  return s.replace(E164, (m) => `${m.slice(0, 3)}[masked]`);
}
export function maskMsisdn(n: string): string {
  return n.length > 5 ? `${n.slice(0, 3)}[masked]` : "[masked]";
}
export const LOG_REDACT_PATHS = [
  "req.headers.authorization", "req.headers.cookie", "headers.authorization",
  "*.phoneNumber", "*.msisdn", "*.client_assertion", "*.access_token", "*.password", "*.secret",
  "phoneNumber", "msisdn", "client_assertion", "access_token",
  "idDocument", "name", "givenName", "familyName", "address", "birthdate", "email", "postalCode", "country", "kyc", "*.kyc",
  // second-wave signals: location and dates are personal data about the subject
  "latitude", "longitude", "radiusMeters", "specifiedDate", "minTenureDays", "area", "params", "*.params", "*.area",
];
