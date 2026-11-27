# Key and certificate rotation
**Owner (proposed)** Head of Security. All rotations below are tested unless stated.
## Participant credentials (public-key registration)
The platform never holds a participant private key. Rotation: the participant (or an integration engineer) requests registration of a NEW public key, bound to the client certificate thumbprint, with `rotateOutKid` = the old key. A second person approves. The old key's expiry is cut to a 60-minute overlap. Revocation of a compromised key is immediate and single-person. Expiring keys (30 days) are flagged on the Credentials page and by an alert.
## Platform token-signing key
`kms.rotate("token-signing-ec")` creates a new version; new tokens use it; tokens signed with the previous version stay valid until they expire (at most 5 minutes) because the key set exposes current and previous keys (tested). Then retire the old version.
## Field-encryption keys
`kms.rotate(name)` adds a version; old ciphertext still decrypts; new writes use the new version (tested). Re-encrypt old data in a controlled job if required.
## Number-hashing key (msisdn-hmac)
Not rotated in place: hashes must stay stable. Rotation needs a re-hash migration of consents and porting data, which is not implemented. The admin portal process shares this key (residual risk R-011).
## TLS certificates
Server and client certificates: issue new ones, register the new client certificate thumbprint with the new public key (two-person), switch over, revoke the old. Telco certificates: outbound trust is the deployment CA bundle (no per-telco pinning yet, R-013).
## Database passwords
Generated at setup; rotate by re-running role setup in the target environment and updating the secret store. The migration role is used only for migrations.
