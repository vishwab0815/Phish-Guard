import type { Metadata } from 'next'
import { Outfit } from 'next/font/google'
import './globals.css'
import { ThemeProvider } from '@/providers/theme-provider'
import { Toaster } from '@/components/ui/sonner'

const outfit = Outfit({ subsets: ['latin'] })

const SITE_TITLE = 'PhishGuard — Check suspicious links, SMS and emails'
const SITE_DESCRIPTION =
  'Free scam checker for India. Paste a suspicious link, SMS, WhatsApp message, email or file and get a plain-language verdict and what to do next. No sign-up, nothing stored on our servers.'

export const metadata: Metadata = {
  metadataBase: new URL('https://phishguard-in.vercel.app'),
  title: SITE_TITLE,
  description: SITE_DESCRIPTION,
  applicationName: 'PhishGuard',
  openGraph: {
    type: 'website',
    url: '/',
    siteName: 'PhishGuard',
    title: SITE_TITLE,
    description: SITE_DESCRIPTION,
    locale: 'en_IN',
  },
  twitter: {
    card: 'summary',
    title: SITE_TITLE,
    description: SITE_DESCRIPTION,
  },
  icons: {
    icon: '/favicon.ico',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${outfit.className} dark:mesh-gradient cyber-grid min-h-screen antialiased`}>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {children}
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  )
}
