# SkySecurity Policy Core

**Status: engineering beta / major-application domain core.**

SkySecurity Policy Core is a small TypeScript authorization-policy primitive for SKYCOIN4444. It validates bounded subject/resource/action facts and evaluates explicit allow rules using a default-deny policy.

Implemented: strict identifier validation, role-aware allow rules, duplicate-rule rejection, deterministic decisions, strict TypeScript tests/build, and dependency-audit CI. Every decision reports `enforcementPerformed: false` because this package makes a policy decision only.

Not implemented or claimed: authentication, identity proofing, MFA, JWT/session validation, network enforcement, WAF/IDS/IPS, malware scanning, vulnerability scanning, secrets management, cryptography, SIEM/SOC operations, durable audit logs, tenant isolation, compliance certification, independent security assessment, HA, or production deployment.

```bash
npm install --ignore-scripts
npm run check
```

A consuming service must authenticate callers, supply trusted identity/role facts, protect policy configuration, enforce the returned decision, log security-relevant events, and independently validate its own security controls.
