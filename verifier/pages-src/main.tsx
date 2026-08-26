import React from 'react';
import { createRoot } from 'react-dom/client';

import VerifierPage from '../app/page';
import '../app/globals.css';

const root = document.getElementById('root');

if (!root) {
  throw new Error('Verifier root element is missing.');
}

createRoot(root).render(
  <React.StrictMode>
    <VerifierPage />
  </React.StrictMode>,
);
