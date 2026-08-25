export interface AccessRequest { subject: string; resource: string; action: string; roles?: readonly string[] }
export interface AllowRule { id: string; resource: string; action: string; roles: readonly string[] }
export interface Decision { allowed: boolean; reason: "matched_rule" | "default_deny"; ruleId?: string; enforcementPerformed: false }

const TOKEN = /^[A-Za-z0-9._:/-]{1,128}$/;

function token(value: string, label: string): string {
  const normalized = value.trim();
  if (!TOKEN.test(normalized)) throw new Error(`invalid ${label}`);
  return normalized;
}

export function evaluate(request: AccessRequest, rules: readonly AllowRule[]): Decision {
  const resource = token(request.resource, "resource");
  const action = token(request.action, "action");
  token(request.subject, "subject");
  if (rules.length > 1000) throw new Error("rule limit exceeded");
  const roles = new Set((request.roles ?? []).map((role) => token(role, "role")));
  for (const rule of rules) {
    token(rule.id, "rule id");
    if (token(rule.resource, "rule resource") !== resource || token(rule.action, "rule action") !== action) continue;
    if (rule.roles.length === 0 || rule.roles.some((role) => roles.has(token(role, "rule role")))) {
      return { allowed: true, reason: "matched_rule", ruleId: rule.id, enforcementPerformed: false };
    }
  }
  return { allowed: false, reason: "default_deny", enforcementPerformed: false };
}

export function validateRules(rules: readonly AllowRule[]) {
  if (rules.length > 1000) throw new Error("rule limit exceeded");
  const seen = new Set<string>();
  for (const rule of rules) {
    const id = token(rule.id, "rule id");
    if (seen.has(id)) throw new Error("duplicate rule id");
    seen.add(id);
    token(rule.resource, "rule resource");
    token(rule.action, "rule action");
    if (rule.roles.length > 64) throw new Error("role limit exceeded");
    rule.roles.forEach((role) => token(role, "rule role"));
  }
  return { valid: true as const, ruleCount: rules.length };
}

export * from './secrets.js';
