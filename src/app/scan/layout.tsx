import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: { absolute: 'Scanner — PhishGuard' },
  description:
    'Check a suspicious link, email, message or file and get a plain-language verdict with what to do next. Demo — results stay on this device.',
}

export default function ScanLayout({ children }: { children: React.ReactNode }) {
  return children
}
