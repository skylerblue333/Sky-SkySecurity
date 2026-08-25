export type SecretReference = {
  name: string;
  provider: 'env' | 'vault' | 'kms' | 'external';
  path: string;
  required?: boolean;
};

export type SecretPolicy = {
  allowedProviders: SecretReference['provider'][];
  forbiddenNameFragments?: string[];
};

export type SecretValidationResult = {
  valid: boolean;
  errors: string[];
};

const SECRET_NAME = /^[A-Z][A-Z0-9_]{2,127}$/;

export function validateSecretReference(
  ref: SecretReference,
  policy: SecretPolicy,
): SecretValidationResult {
  const errors: string[] = [];

  if (!SECRET_NAME.test(ref.name)) {
    errors.push('secret name must be uppercase snake case and 3-128 characters');
  }

  if (!policy.allowedProviders.includes(ref.provider)) {
    errors.push(`provider ${ref.provider} is not allowed`);
  }

  if (!ref.path.trim()) {
    errors.push('secret path is required');
  }

  for (const fragment of policy.forbiddenNameFragments ?? []) {
    if (ref.name.includes(fragment.toUpperCase())) {
      errors.push(`secret name contains forbidden fragment: ${fragment}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

export function redactSecretValue(value: string): string {
  if (value.length <= 4) return '****';
  return `${value.slice(0, 2)}${'*'.repeat(Math.min(12, value.length - 4))}${value.slice(-2)}`;
}

export function buildSecretResolutionPlan(
  refs: SecretReference[],
  policy: SecretPolicy,
) {
  const seen = new Set<string>();

  return refs.map((ref) => {
    const validation = validateSecretReference(ref, policy);
    const duplicate = seen.has(ref.name);
    seen.add(ref.name);

    return {
      name: ref.name,
      provider: ref.provider,
      path: ref.path,
      required: ref.required ?? true,
      valid: validation.valid && !duplicate,
      errors: duplicate ? [...validation.errors, 'duplicate secret name'] : validation.errors,
    };
  });
}
