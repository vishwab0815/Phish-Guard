import type { Metadata } from 'next'
import { Outfit } from 'next/font/google'
import './globals.css'
import { ThemeProvider } from '@/providers/theme-provider'
import { Toaster } from '@/components/ui/sonner'

const outfit = Outfit({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'PhishGuard - AI-Powered Phishing Detection',
  description: 'Advanced phishing detection application powered by AI to protect your digital environment',
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
      <body className={`${outfit.className} mesh-gradient cyber-grid min-h-screen antialiased`}>
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
