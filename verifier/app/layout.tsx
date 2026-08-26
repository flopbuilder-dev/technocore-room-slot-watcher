import type { Metadata } from 'next';

import './globals.css';

export const dynamic = 'force-static';

export const metadata: Metadata = {
  metadataBase: new URL('https://flopbuilder-dev.github.io/technocore-room-slot-watcher/'),
  title: 'Proofcheck — Technocore V3 Proof Verifier',
  description: 'Verify Technocore V3 contribution proofs privately and entirely in your browser.',
  openGraph: {
    title: 'Trust the signature. Not the server.',
    description: 'Technocore V3 Proof Verifier — private, on-device Ed25519 verification.',
    type: 'website',
    images: [
      {
        url: 'technocore-v3-social-preview.png',
        width: 1200,
        height: 630,
        alt: 'Technocore V3 Proof Verifier',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Trust the signature. Not the server.',
    description: 'Technocore V3 Proof Verifier — private, on-device Ed25519 verification.',
    images: ['technocore-v3-social-preview.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
