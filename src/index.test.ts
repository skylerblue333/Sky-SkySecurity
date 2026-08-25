import assert from "node:assert/strict";
import test from "node:test";
import { evaluate, validateRules } from "./index.js";

const rules = [{ id: "read-dashboard", resource: "dashboard", action: "read", roles: ["analyst"] }];

test("defaults to deny", () => {
  assert.deepEqual(evaluate({ subject: "u1", resource: "dashboard", action: "read", roles: ["guest"] }, rules), {
    allowed: false, reason: "default_deny", enforcementPerformed: false,
  });
});

test("allows only a matching role rule without claiming enforcement", () => {
  const decision = evaluate({ subject: "u1", resource: "dashboard", action: "read", roles: ["analyst"] }, rules);
  assert.equal(decision.allowed, true);
  assert.equal(decision.ruleId, "read-dashboard");
  assert.equal(decision.enforcementPerformed, false);
});

test("duplicate and malformed rules fail closed", () => {
  assert.throws(() => validateRules([...rules, ...rules]), /duplicate/);
  assert.throws(() => evaluate({ subject: "", resource: "dashboard", action: "read" }, rules), /subject/);
});
