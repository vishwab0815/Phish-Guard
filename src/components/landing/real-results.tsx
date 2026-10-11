import Link from 'next/link'
import { ArrowRight, Link2, Mail } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { Reveal } from './reveal'
import { Container, SectionHeading, VerdictBadge, focusRing, surfaceCard, type Verdict } from './primitives'

type Result = {
  kind: 'Link' | 'Email'
  target: string
  note?: string
  verdict: Verdict
  score?: number
  why: string
}

const RESULTS: Result[] = [
  {
    kind: 'Link',
    target: 'paypa1-secure-login.xyz/verify',
    verdict: 'critical',
    score: 100,
    why: 'Typosquat of PayPal — a “1” in place of the “l”.',
  },
  {
    kind: 'Link',
    // First letter is the Cyrillic "а" (U+0430), not Latin "a".
    target: 'аpple.com',
    note: 'first letter is Cyrillic “а”',
    verdict: 'critical',
    score: 83,
    why: 'Unicode look-alike of apple.com.',
  },
  {
    kind: 'Link',
    target: 'sbi-kyc-update.top/aadhaar',
    verdict: 'critical',
    score: 100,
    why: 'Impersonates SBI with a KYC / Aadhaar lure.',
  },
  {
    kind: 'Link',
    target: 'testsafebrowsing.appspot.com/s/phishing.html',
    note: 'Google’s official phishing test page',
    verdict: 'critical',
    score: 90,
    why: 'Flagged by Google Safe Browsing and 10 of 93 VirusTotal engines.',
  },
  {
    kind: 'Email',
    target: '“SBI Bank” <…@gmail.com>',
    note: 'fake bank email asking for an OTP',
    verdict: 'critical',
    why: 'A bank name sent from a free Gmail address, asking for your OTP.',
  },
  {
    kind: 'Link',
    target: 'onlinesbi.sbi',
    verdict: 'safe',
    why: 'The real SBI internet banking site.',
  },
  {
    kind: 'Link',
    target: 'login.microsoftonline.com',
    verdict: 'safe',
    why: 'Microsoft’s real sign-in page.',
  },
]

export function RealResults() {
  return (
    <section id="results" aria-labelledby="results-title" className="scroll-mt-20 py-20 sm:py-28">
      <Container>
        <SectionHeading
          id="results-title"
          eyebrow="Real results"
          title="Catches the fakes. Leaves the real sites alone."
          description="Genuine outputs from the PhishGuard engine — including real bank and login pages it correctly marks as safe."
        />

        <Reveal className="mt-14">
          <div className={cn(surfaceCard, 'overflow-hidden')}>
            <div
              className="hidden grid-cols-[minmax(0,1.25fr)_minmax(0,1.5fr)_auto] gap-6 border-b border-border bg-muted/40 px-6 py-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground lg:grid dark:border-white/10 dark:bg-white/[0.03]"
              aria-hidden="true"
            >
              <span>What was checked</span>
              <span>Why</span>
              <span className="w-[150px] text-right">Verdict</span>
            </div>
            <ul className="divide-y divide-border dark:divide-white/10">
              {RESULTS.map((r) => {
                const Icon = r.kind === 'Email' ? Mail : Link2
                return (
                  <li
                    key={r.target}
                    className="grid gap-3 px-5 py-4 transition-colors hover:bg-muted/30 sm:px-6 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1.5fr)_auto] lg:items-center lg:gap-6 dark:hover:bg-white/[0.02]"
                  >
                    <div className="flex min-w-0 items-start gap-3">
                      <span
                        className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground dark:bg-white/5"
                        title={r.kind}
                      >
                        <Icon className="h-4 w-4" aria-hidden="true" />
                        <span className="sr-only">{r.kind}:</span>
                      </span>
                      <div className="min-w-0">
                        <p className="break-all font-mono text-sm text-foreground">{r.target}</p>
                        {r.note ? <p className="mt-0.5 text-xs text-muted-foreground">{r.note}</p> : null}
                      </div>
                    </div>
                    <p className="text-sm leading-relaxed text-muted-foreground">{r.why}</p>
                    <div className="flex items-center gap-3 lg:w-[150px] lg:justify-end">
                      <VerdictBadge verdict={r.verdict} />
                      {typeof r.score === 'number' ? (
                        <span className="font-mono text-sm tabular-nums text-foreground">
                          {r.score}
                          <span className="text-muted-foreground">/100</span>
                          <span className="sr-only"> risk score</span>
                        </span>
                      ) : null}
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>
        </Reveal>

        <div className="mt-6 flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
          <p className="max-w-2xl text-sm text-muted-foreground">
            Some checks use live threat databases, so scores can change over time. Results are guidance, not a
            guarantee.
          </p>
          <Link
            href="/scan"
            className={cn(
              'group inline-flex shrink-0 items-center gap-1.5 rounded-md text-sm font-semibold text-violet-700 dark:text-violet-300',
              focusRing,
            )}
          >
            Try your own
            <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
          </Link>
        </div>
      </Container>
    </section>
  )
}
