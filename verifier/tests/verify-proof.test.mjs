import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createEvidenceText,
  parseProofJson,
  verifyProof,
} from '../lib/verify-proof.mjs';

const fixtureUrl = new URL(
  './fixtures/technocore-room-slot-watcher-v3.0.0-proof.json',
  import.meta.url,
);
const evidenceUrl = new URL(
  './fixtures/technocore-room-slot-watcher-v3.0.0-evidence.txt',
  import.meta.url,
);
const releasedProof = JSON.parse(
  await readFile(fileURLToPath(fixtureUrl), 'utf8'),
);
const releasedEvidence = await readFile(fileURLToPath(evidenceUrl), 'utf8');

function cloneProof() {
  return structuredClone(releasedProof);
}

function corruptBase64Url(value) {
  const bytes = Buffer.from(value, 'base64url');
  bytes[0] ^= 0x01;
  return bytes.toString('base64url');
}

function normalizedLines(value) {
  return value.replaceAll('\r\n', '\n');
}

test('genuine released V3.0.0 proof passes and reproduces its evidence', async () => {
  const result = await verifyProof(cloneProof());

  assert.equal(result.overall, 'VERIFIED');
  assert.equal(result.contributionSignature, 'VALID');
  assert.equal(result.recordSignature, 'VALID');
  assert.equal(result.errorType, null);
  assert.equal(
    normalizedLines(createEvidenceText(releasedProof, result)),
    normalizedLines(releasedEvidence),
  );
});

test('modified technocore text fails as invalid proof format', async () => {
  const proof = cloneProof();
  proof.technocore.text += ' tampered';
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.errorType, 'INVALID_PROOF_FORMAT');
});

test('modified technocore nonce fails record signature verification', async () => {
  const proof = cloneProof();
  proof.technocore.nonce = '1787749697039';
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.contributionSignature, 'VALID');
  assert.equal(result.recordSignature, 'INVALID');
  assert.equal(result.errorType, 'INVALID_SIGNATURE');
});

test('modified technocore room fails record signature verification', async () => {
  const proof = cloneProof();
  proof.technocore.room = 'technocore-alt';
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.contributionSignature, 'VALID');
  assert.equal(result.recordSignature, 'INVALID');
});

test('modified top-level commit fails canonical proof validation', async () => {
  const proof = cloneProof();
  proof.commit = proof.commit.replace(/^c/, 'd');
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.errorType, 'INVALID_PROOF_FORMAT');
});

test('modified DID fails signature verification cleanly', async () => {
  const proof = cloneProof();
  proof.did = proof.did.slice(0, -1) + 'u';
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.notEqual(result.errorType, null);
});

test('corrupted contribution signature fails cryptographically', async () => {
  const proof = cloneProof();
  proof.signature = corruptBase64Url(proof.signature);
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.contributionSignature, 'INVALID');
  assert.equal(result.recordSignature, 'INVALID');
  assert.equal(result.errorType, 'INVALID_SIGNATURE');
});

test('corrupted record signature fails cryptographically', async () => {
  const proof = cloneProof();
  proof.record_signature = corruptBase64Url(proof.record_signature);
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.contributionSignature, 'VALID');
  assert.equal(result.recordSignature, 'INVALID');
  assert.equal(result.errorType, 'INVALID_SIGNATURE');
});

test('missing required fields returns invalid proof format without a crash', async () => {
  const proof = cloneProof();
  delete proof.signature;
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.errorType, 'INVALID_PROOF_FORMAT');
  assert.match(result.message, /missing field/i);
});

test('unsupported schema is rejected clearly', async () => {
  const proof = cloneProof();
  proof.schema = 'technocore-contribution-proof/v2';
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.errorType, 'UNSUPPORTED_PROOF');
  assert.match(result.message, /unsupported proof schema/i);
});

test('malformed signature encoding is rejected as invalid proof format', async () => {
  const proof = cloneProof();
  proof.signature = '**not-base64url**';
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.errorType, 'INVALID_PROOF_FORMAT');
  assert.match(result.message, /base64url/i);
});

test('malformed record signature encoding is rejected as invalid proof format', async () => {
  const proof = cloneProof();
  proof.record_signature = 'not+base64url';
  const result = await verifyProof(proof);

  assert.equal(result.overall, 'INVALID');
  assert.equal(result.errorType, 'INVALID_PROOF_FORMAT');
  assert.match(result.message, /base64url/i);
});

test('invalid JSON is classified as invalid proof format', () => {
  assert.throws(
    () => parseProofJson('{not-json}'),
    (error) => error.type === 'INVALID_PROOF_FORMAT',
  );
});
