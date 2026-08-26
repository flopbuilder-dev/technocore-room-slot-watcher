const PROOF_SCHEMA = 'technocore-contribution-proof/v1';
const PROOF_ALGORITHM = 'Ed25519';
const ROOM_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const DID_PATTERN = /^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/;
const COMMIT_PATTERN = /^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/;
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = new Map(
  [...BASE58_ALPHABET].map((character, index) => [character, index]),
);
const TOP_LEVEL_FIELDS = [
  'schema',
  'did',
  'repository',
  'commit',
  'commit_url',
  'created_at',
  'signature_algorithm',
  'signature',
  'technocore',
  'record_signature',
];
const RECORD_FIELDS = [
  'status',
  'room',
  'seq',
  'nonce',
  'timestamp',
  'text',
];

export class ProofValidationError extends Error {
  constructor(type, message) {
    super(message);
    this.name = 'ProofValidationError';
    this.type = type;
  }
}

function invalidFormat(message) {
  throw new ProofValidationError('INVALID_PROOF_FORMAT', message);
}

function unsupported(message) {
  throw new ProofValidationError('UNSUPPORTED_PROOF', message);
}

function assertExactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    invalidFormat(`${label} must be a JSON object.`);
  }

  const actual = Object.keys(value);
  const missing = expected.filter((field) => !actual.includes(field));
  const unexpected = actual.filter((field) => !expected.includes(field));

  if (missing.length) {
    invalidFormat(`${label} is missing field(s): ${missing.join(', ')}.`);
  }

  if (unexpected.length) {
    invalidFormat(
      `${label} contains unexpected field(s): ${unexpected.join(', ')}.`,
    );
  }
}

function normalizeRepositoryUrl(repository) {
  if (typeof repository !== 'string') {
    invalidFormat('Repository must be a public HTTPS URL.');
  }

  let value = repository.trim().replace(/\/+$/, '');

  if (value.endsWith('.git')) {
    value = value.slice(0, -4);
  }

  let parsed;

  try {
    parsed = new URL(value);
  } catch {
    invalidFormat('Repository must be a valid public HTTPS URL.');
  }

  if (
    parsed.protocol !== 'https:' ||
    !parsed.host ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    invalidFormat(
      'Repository must be public HTTPS without credentials, query, or fragment.',
    );
  }

  if (!parsed.pathname.replaceAll('/', '')) {
    invalidFormat('Repository URL must include a repository path.');
  }

  return value;
}

function normalizeCommitHash(commit) {
  if (typeof commit !== 'string') {
    invalidFormat('Commit hash must be a string.');
  }

  const value = commit.trim().toLowerCase();

  if (!COMMIT_PATTERN.test(value)) {
    invalidFormat('Commit hash must contain exactly 40 or 64 hex characters.');
  }

  return value;
}

function commitUrlFor(repository, commit) {
  const parsed = new URL(repository);
  const separator =
    parsed.hostname === 'gitlab.com' ? '/-/commit/' : '/commit/';
  return repository.replace(/\/+$/, '') + separator + commit;
}

function sortedJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortedJsonValue);
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortedJsonValue(value[key])]),
    );
  }

  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(sortedJsonValue(value));
}

function base58Decode(value) {
  if (!value) {
    invalidFormat('DID base58 value is empty.');
  }

  let number = 0n;

  for (const character of value) {
    const digit = BASE58_INDEX.get(character);

    if (digit === undefined) {
      invalidFormat('DID contains an invalid base58 character.');
    }

    number = number * 58n + BigInt(digit);
  }

  const decoded = [];

  while (number > 0n) {
    decoded.unshift(Number(number & 255n));
    number >>= 8n;
  }

  const leadingZeroes = value.length - value.replace(/^1+/, '').length;
  return new Uint8Array([
    ...new Array(leadingZeroes).fill(0),
    ...decoded,
  ]);
}

function publicKeyBytesFromDid(did) {
  if (typeof did !== 'string' || !DID_PATTERN.test(did)) {
    invalidFormat('Proof contains an invalid Ed25519 did:key.');
  }

  const decoded = base58Decode(did.slice('did:key:z'.length));

  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    invalidFormat('Proof DID is not an Ed25519 did:key.');
  }

  return decoded.slice(2);
}

function base64UrlDecode(value, fieldName) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    invalidFormat(`${fieldName} is not valid unpadded base64url.`);
  }

  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  let decoded;

  try {
    decoded = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  } catch {
    invalidFormat(`${fieldName} is not valid unpadded base64url.`);
  }

  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));

  if (bytes.length !== 64) {
    invalidFormat(`${fieldName} must decode to a 64-byte Ed25519 signature.`);
  }

  return bytes;
}

function validateTimestamp(value, fieldName) {
  if (
    typeof value !== 'string' ||
    !value.endsWith('Z') ||
    Number.isNaN(Date.parse(value))
  ) {
    invalidFormat(`${fieldName} must be a valid UTC timestamp ending in Z.`);
  }
}

function proofCore(document) {
  return {
    schema: document.schema,
    did: document.did,
    repository: document.repository,
    commit: document.commit,
    commit_url: document.commit_url,
    created_at: document.created_at,
  };
}

function proofEnvelope(document) {
  return {
    schema: document.schema,
    did: document.did,
    repository: document.repository,
    commit: document.commit,
    commit_url: document.commit_url,
    created_at: document.created_at,
    signature_algorithm: document.signature_algorithm,
    signature: document.signature,
    technocore: document.technocore,
  };
}

function proofMessageText(document) {
  return `Signed contribution proof: ${document.commit_url}`;
}

function validateTechnocoreRecord(document) {
  const record = document.technocore;

  if (record === null) {
    return;
  }

  assertExactFields(record, RECORD_FIELDS, 'Technocore record');

  if (!['confirmed', 'confirmed-after-timeout', 'uncertain'].includes(record.status)) {
    invalidFormat('Technocore publication status is invalid.');
  }

  if (typeof record.room !== 'string' || !ROOM_PATTERN.test(record.room)) {
    invalidFormat('Technocore room is invalid.');
  }

  if (typeof record.nonce !== 'string' || !/^\d+$/.test(record.nonce)) {
    invalidFormat('Technocore nonce is invalid.');
  }

  if (record.text !== proofMessageText(document)) {
    invalidFormat('Technocore text does not match the proof commit URL.');
  }

  if (record.status.startsWith('confirmed')) {
    if (!Number.isInteger(record.seq) || record.seq <= 0) {
      invalidFormat('Confirmed Technocore sequence must be a positive integer.');
    }

    validateTimestamp(record.timestamp, 'Technocore timestamp');
  } else if (record.seq !== null || record.timestamp !== null) {
    invalidFormat(
      'Uncertain Technocore records cannot claim a sequence or timestamp.',
    );
  }
}

function validateDocument(document) {
  assertExactFields(document, TOP_LEVEL_FIELDS, 'Proof');

  if (document.schema !== PROOF_SCHEMA) {
    unsupported(`Unsupported proof schema: ${String(document.schema)}.`);
  }

  if (document.signature_algorithm !== PROOF_ALGORITHM) {
    unsupported(
      `Unsupported signature algorithm: ${String(document.signature_algorithm)}.`,
    );
  }

  const repository = normalizeRepositoryUrl(document.repository);
  const commit = normalizeCommitHash(document.commit);

  if (document.repository !== repository) {
    invalidFormat('Repository URL is not in canonical form.');
  }

  if (document.commit !== commit) {
    invalidFormat('Commit hash must use canonical lowercase hexadecimal.');
  }

  if (document.commit_url !== commitUrlFor(repository, commit)) {
    invalidFormat('Commit URL does not match the repository and commit.');
  }

  validateTimestamp(document.created_at, 'Proof creation time');
  validateTechnocoreRecord(document);

  return {
    publicKeyBytes: publicKeyBytesFromDid(document.did),
    signature: base64UrlDecode(document.signature, 'Contribution signature'),
    recordSignature: base64UrlDecode(
      document.record_signature,
      'Technocore record signature',
    ),
  };
}

function invalidResult(type, message) {
  return {
    overall: 'INVALID',
    contributionSignature: 'NOT_CHECKED',
    recordSignature: 'NOT_CHECKED',
    errorType: type,
    message,
  };
}

export async function verifyProof(document) {
  let validated;

  try {
    validated = validateDocument(document);
  } catch (error) {
    if (error instanceof ProofValidationError) {
      return invalidResult(error.type, error.message);
    }

    return invalidResult(
      'INVALID_PROOF_FORMAT',
      'Proof validation failed without exposing private data.',
    );
  }

  try {
    const publicKey = await crypto.subtle.importKey(
      'raw',
      validated.publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const encoder = new TextEncoder();
    const contributionValid = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      validated.signature,
      encoder.encode(canonicalJson(proofCore(document))),
    );
    const recordValid = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      validated.recordSignature,
      encoder.encode(canonicalJson(proofEnvelope(document))),
    );
    const verified = contributionValid && recordValid;

    return {
      overall: verified ? 'VERIFIED' : 'INVALID',
      contributionSignature: contributionValid ? 'VALID' : 'INVALID',
      recordSignature: recordValid ? 'VALID' : 'INVALID',
      errorType: verified ? null : 'INVALID_SIGNATURE',
      message: verified
        ? 'Both Ed25519 signatures are valid.'
        : 'One or more Ed25519 signatures are invalid.',
    };
  } catch {
    return invalidResult(
      'CRYPTOGRAPHY_UNAVAILABLE',
      'This browser cannot perform Ed25519 verification.',
    );
  }
}

export function createEvidenceText(document, result) {
  if (result.overall !== 'VERIFIED') {
    throw new ProofValidationError(
      'INVALID_SIGNATURE',
      'Evidence can be reproduced only from a verified proof.',
    );
  }

  const record = document.technocore;
  const lines = [
    'TECHNOCORE CONTRIBUTION PROOF',
    '',
    `Schema: ${document.schema}`,
    `DID: ${document.did}`,
    `Repository: ${document.repository}`,
    `Commit: ${document.commit}`,
    `Commit URL: ${document.commit_url}`,
    `Created at: ${document.created_at}`,
    `Signature algorithm: ${document.signature_algorithm}`,
    'Local signature: VALID',
    'Evidence-record signature: VALID',
  ];

  if (record === null) {
    lines.push('', 'Technocore publication: NOT REQUESTED');
  } else {
    lines.push(
      '',
      `Technocore publication: ${record.status.toUpperCase()}`,
      `Room: ${record.room}`,
      `Sequence: ${record.seq || 'unconfirmed'}`,
      `Nonce: ${record.nonce}`,
      `Timestamp: ${record.timestamp || 'unconfirmed'}`,
      `Message: ${record.text}`,
    );
  }

  lines.push(
    '',
    'This file contains public verification data only.',
    'It does not contain a private key, seed, or password.',
    '',
  );
  return lines.join('\n');
}

export function parseProofJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new ProofValidationError(
      'INVALID_PROOF_FORMAT',
      'The selected file is not valid JSON.',
    );
  }
}
