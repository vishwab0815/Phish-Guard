import Link from 'next/link'
import { Shield } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { Container, focusRing } from './primitives'

const linkClass = cn('rounded text-sm text-muted-foreground transition-colors hover:text-foreground', focusRing)

const SCANNER_LINKS = [
  { href: '/scan', label: 'Open scanner' },
  { href: '/scan?type=url', label: 'Check a link' },
  { href: '/scan?type=message', label: 'Check an SMS' },
  { href: '/scan?type=email', label: 'Check an email' },
  { href: '/scan?type=file', label: 'Check a file' },
  { href: '/scan?tab=assistant', label: 'AI assistant' },
] as const

const HELP_LINKS = [
  { href: 'https://cybercrime.gov.in', label: 'cybercrime.gov.in' },
  { href: 'https://sancharsaathi.gov.in', label: 'Sanchar Saathi (Chakshu)' },
] as const

export function SiteFooter() {
  return (
    <footer className="border-t border-border/60 bg-muted/20 dark:border-white/10 dark:bg-white/[0.01]">
      <Container className="py-12">
        <div className="grid gap-10 md:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)]">
          <div className="max-w-sm">
            <Link href="/" className={cn('inline-flex items-center gap-2 rounded-lg', focusRing)}>
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-blue-600 to-violet-600">
                <Shield className="h-[18px] w-[18px] text-white" aria-hidden="true" />
              </span>
              <span className="font-display text-lg text-foreground">PhishGuard</span>
            </Link>
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
              Check suspicious links, SMS, emails and files — and get a plain-language verdict with what to do
              next.
            </p>
          </div>

          <nav aria-label="Scanner">
            <h2 className="text-sm font-semibold text-foreground">Scanner</h2>
            <ul className="mt-4 space-y-2.5">
              {SCANNER_LINKS.map((l) => (
                <li key={l.href}>
                  <Link href={l.href} className={linkClass}>
                    {l.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>

          <nav aria-label="Get help">
            <h2 className="text-sm font-semibold text-foreground">Get help</h2>
            <ul className="mt-4 space-y-2.5">
              <li>
                <a href="tel:1930" className={cn(linkClass, 'font-semibold text-red-700 dark:text-red-300')}>
                  Call 1930 (Cyber Crime Helpline)
                </a>
              </li>
              {HELP_LINKS.map((l) => (
                <li key={l.href}>
                  <a href={l.href} target="_blank" rel="noopener noreferrer" className={linkClass}>
                    {l.label}
                    <span className="sr-only"> (opens in a new tab)</span>
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        <div className="mt-12 border-t border-border/60 pt-6 text-xs leading-relaxed text-muted-foreground dark:border-white/10">
          <p>
            © 2026 PhishGuard · Demo project — results are guidance, not a guarantee · Nothing is stored on our
            servers; your scan history stays in your own browser.
          </p>
        </div>
      </Container>
    </footer>
  )
}
