'use client';

import { useRef, useState } from 'react';

import { parseProofJson, verifyProof } from '@/lib/verify-proof.mjs';
import releasedProof from '@/tests/fixtures/technocore-room-slot-watcher-v3.0.0-proof.json';

type SignatureState = 'VALID' | 'INVALID' | 'NOT_CHECKED';
type VerificationResult = {
  overall: 'VERIFIED' | 'INVALID';
  contributionSignature: SignatureState;
  recordSignature: SignatureState;
  errorType: string | null;
  message: string;
};
type ProofDocument = {
  did?: string;
  repository?: string;
  commit?: string;
  commit_url?: string;
  created_at?: string;
  technocore?: {
    room?: string;
    seq?: number;
    nonce?: string;
    timestamp?: string;
  } | null;
};

function stateClass(state: SignatureState | 'VERIFIED' | 'INVALID') {
  if (state === 'VALID' || state === 'VERIFIED') return 'is-valid';
  if (state === 'INVALID') return 'is-invalid';
  return 'is-neutral';
}

function shortValue(value: string | undefined, start = 12, end = 9) {
  if (!value || value.length <= start + end + 1) return value || '—';
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

export default function Home() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [proof, setProof] = useState<ProofDocument | null>(null);
  const [fileName, setFileName] = useState('No proof selected');
  const [isDragging, setIsDragging] = useState(false);
  const [isWorking, setIsWorking] = useState(false);

  async function verifyText(text: string, sourceName: string) {
    setIsWorking(true);
    setFileName(sourceName);
    try {
      const parsed = parseProofJson(text) as ProofDocument;
      const verification = (await verifyProof(parsed)) as VerificationResult;
      setProof(parsed);
      setResult(verification);
    } catch (error) {
      const message =
        error && typeof error === 'object' && 'message' in error
          ? String(error.message)
          : 'The selected file could not be read.';
      const errorType =
        error && typeof error === 'object' && 'type' in error
          ? String(error.type)
          : 'INVALID_PROOF_FORMAT';
      setProof(null);
      setResult({
        overall: 'INVALID',
        contributionSignature: 'NOT_CHECKED',
        recordSignature: 'NOT_CHECKED',
        errorType,
        message,
      });
    } finally {
      setIsWorking(false);
    }
  }

  async function processFile(file: File | undefined) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.json')) {
      setFileName(file.name);
      setProof(null);
      setResult({
        overall: 'INVALID',
        contributionSignature: 'NOT_CHECKED',
        recordSignature: 'NOT_CHECKED',
        errorType: 'INVALID_PROOF_FORMAT',
        message: 'Select a .json contribution-proof file.',
      });
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setFileName(file.name);
      setProof(null);
      setResult({
        overall: 'INVALID',
        contributionSignature: 'NOT_CHECKED',
        recordSignature: 'NOT_CHECKED',
        errorType: 'INVALID_PROOF_FORMAT',
        message: 'The proof file is larger than the 2 MB safety limit.',
      });
      return;
    }
    await verifyText(await file.text(), file.name);
  }

  async function loadReleasedExample() {
    await verifyText(JSON.stringify(releasedProof), 'Released V3.0.0 proof');
  }

  return (
    <main>
      <header className="site-header">
        <a className="brand" href="#top" aria-label="Proofcheck home">
          <span className="brand-mark" aria-hidden="true"><span /></span>
          <span><strong>Proofcheck</strong><small>Technocore · V3.1</small></span>
        </a>
        <a className="source-link" href="https://github.com/flopbuilder-dev/technocore-room-slot-watcher" target="_blank" rel="noreferrer">
          View source <span aria-hidden="true">↗</span>
        </a>
      </header>

      <section className="hero" id="top">
        <p className="eyebrow"><span /> Client-side Ed25519 verification</p>
        <h1>Trust the signature.<br />Not the server.</h1>
        <p className="hero-copy">
          Verify a Technocore V3 contribution proof against its embedded
          <code> did:key</code>. No account, backend, or network lookup required.
        </p>
        <div className="privacy-banner" role="note">
          <span className="privacy-icon" aria-hidden="true">⌁</span>
          <div><strong>Your proof stays on this device.</strong><span> File contents are read in memory and never uploaded.</span></div>
          <span className="local-chip">LOCAL ONLY</span>
        </div>
      </section>

      <section className="verifier-shell" aria-label="Proof verifier">
        <div className="input-panel">
          <div className="panel-heading">
            <div><span className="step-number">01</span><h2>Select a proof</h2></div>
            <span className="format-label">.JSON</span>
          </div>
          <input
            ref={inputRef}
            className="sr-only"
            type="file"
            accept="application/json,.json"
            onChange={(event) => processFile(event.target.files?.[0])}
          />
          <button
            type="button"
            className={`drop-zone ${isDragging ? 'is-dragging' : ''}`}
            onClick={() => inputRef.current?.click()}
            onDragEnter={(event) => { event.preventDefault(); setIsDragging(true); }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(event) => {
              event.preventDefault();
              setIsDragging(false);
              processFile(event.dataTransfer.files[0]);
            }}
          >
            <span className="drop-glyph" aria-hidden="true">↓</span>
            <strong>{isWorking ? 'Verifying…' : 'Drop proof JSON here'}</strong>
            <span>or click to choose a file</span>
            <em>Maximum file size · 2 MB</em>
          </button>
          <div className="file-row" aria-live="polite"><span className="file-dot" /><span>{fileName}</span></div>
          <button type="button" className="example-button" onClick={loadReleasedExample} disabled={isWorking}>
            Test with the released V3.0.0 proof
          </button>
        </div>

        <div className={`result-panel ${result ? stateClass(result.overall) : ''}`}>
          <div className="panel-heading">
            <div><span className="step-number">02</span><h2>Verification result</h2></div>
            <span className="engine-label">WEB CRYPTO</span>
          </div>
          {!result ? (
            <div className="empty-result">
              <span className="result-orbit" aria-hidden="true"><i /></span>
              <strong>Waiting for a proof</strong>
              <p>Both signatures will be checked independently.</p>
            </div>
          ) : (
            <div className="result-content" aria-live="polite">
              <div className="overall-result">
                <span className="result-symbol" aria-hidden="true">{result.overall === 'VERIFIED' ? '✓' : '×'}</span>
                <div><small>OVERALL PROOF</small><strong>{result.overall}</strong></div>
              </div>
              <div className="signature-grid">
                <div><span>Contribution proof signature</span><strong className={stateClass(result.contributionSignature)}>{result.contributionSignature.replace('_', ' ')}</strong></div>
                <div><span>Technocore record signature</span><strong className={stateClass(result.recordSignature)}>{result.recordSignature.replace('_', ' ')}</strong></div>
              </div>
              <p className="result-message"><span>{result.errorType || 'CRYPTOGRAPHICALLY VERIFIED'}</span>{result.message}</p>
            </div>
          )}
        </div>
      </section>

      {proof && (
        <section className="proof-details" aria-label="Proof details">
          <div className="details-heading"><span className="step-number">03</span><div><h2>Proof details</h2><p>Displayed from the selected local file.</p></div></div>
          <dl>
            <div><dt>Agent DID</dt><dd title={proof.did}>{shortValue(proof.did, 20, 12)}</dd></div>
            <div><dt>Commit</dt><dd title={proof.commit}>{shortValue(proof.commit, 12, 10)}</dd></div>
            <div><dt>Repository</dt><dd>{proof.repository || '—'}</dd></div>
            <div><dt>Created</dt><dd>{proof.created_at || '—'}</dd></div>
            <div><dt>Technocore room</dt><dd>{proof.technocore?.room || 'Not published'}</dd></div>
            <div><dt>Sequence</dt><dd>{proof.technocore?.seq || '—'}</dd></div>
          </dl>
        </section>
      )}

      <section className="method-strip">
        <div><span>1</span><p><strong>Parse</strong>Strict V3 schema and canonical fields</p></div>
        <div><span>2</span><p><strong>Decode</strong>Ed25519 key from the public DID</p></div>
        <div><span>3</span><p><strong>Verify</strong>Two canonical signed payloads</p></div>
      </section>
      <footer>
        <p>Open verification for <strong>technocore-contribution-proof/v1</strong></p>
        <p>No analytics · No uploads · No private keys</p>
      </footer>
    </main>
  );
}
