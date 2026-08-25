import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSecretResolutionPlan,
  redactSecretValue,
  validateSecretReference,
} from './secrets.js';

const policy = {
  allowedProviders: ['env', 'vault'] as const,
  forbiddenNameFragments: ['PASSWORD_RAW'],
};

test('accepts a valid reference', () => {
  const result = validateSecretReference(
    { name: 'DATABASE_URL', provider: 'env', path: 'DATABASE_URL' },
    { allowedProviders: [...policy.allowedProviders], forbiddenNameFragments: policy.forbiddenNameFragments },
  );
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test('rejects invalid provider, path, and unsafe naming', () => {
  const result = validateSecretReference(
    { name: 'PASSWORD_RAW_TOKEN', provider: 'kms', path: '   ' },
    { allowedProviders: [...policy.allowedProviders], forbiddenNameFragments: policy.forbiddenNameFragments },
  );
  assert.equal(result.valid, false);
  assert.equal(result.errors.length, 3);
});

test('redacts values without exposing the middle', () => {
  assert.equal(redactSecretValue('abcd'), '****');
  assert.equal(redactSecretValue('super-secret-token'), 'su************en');
});

test('resolution plan rejects duplicate names deterministically', () => {
  const plan = buildSecretResolutionPlan(
    [
      { name: 'API_TOKEN', provider: 'env', path: 'API_TOKEN' },
      { name: 'API_TOKEN', provider: 'vault', path: 'secret/api-token' },
    ],
    { allowedProviders: [...policy.allowedProviders] },
  );
  assert.equal(plan[0].valid, true);
  assert.equal(plan[1].valid, false);
  assert.deepEqual(plan[1].errors, ['duplicate secret name']);
});
