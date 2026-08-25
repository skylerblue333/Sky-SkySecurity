# SkySecrets — Wave 2 Slot #69

SkySecrets is a bounded engineering-beta library for validating secret references, enforcing provider/name policies, redacting secret-like values for display, and producing deterministic resolution plans for SKYCOIN4444 integrations.

## Integration contract

Consumers pass `SecretReference` records and a `SecretPolicy` to `validateSecretReference` or `buildSecretResolutionPlan`. The library returns validation errors and a normalized plan; it does not fetch or store secret values.

## Security boundary

This package is **not** a secrets manager. It does not provide encrypted secret storage, KMS/HSM/Vault connectivity, credential issuance, rotation, revocation, IAM, audit persistence, transport security, production deployment, or proof that downstream callers handle secrets safely. Callers must supply those controls independently.

## Intended SKYCOIN4444 use

Use SkySecrets as a preflight contract before another trusted infrastructure component resolves a configured secret reference. Do not pass raw secrets into logs or persist them through this package.
