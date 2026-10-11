import Link from 'next/link'
import { Check, Mail, MessageSquare, Sparkles } from 'lucide-react'
import { ExampleResultCard } from './example-result-card'
import { QuickCheckForm } from './quick-check-form'
import { Reveal } from './reveal'
import { Container, gradientText, secondaryButton } from './primitives'

const TRUST = ['Free', 'No sign-up', 'Nothing stored on our servers'] as const

export function Hero() {
  return (
    <section aria-labelledby="hero-title" className="relative isolate">
      {/* Decorative background: masked grid + soft colour glows */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10 overflow-hidden">
        <div
          className="absolute inset-0 text-slate-900/[0.06] dark:text-white/[0.06]"
          style={{
            backgroundImage:
              'linear-gradient(to right, currentColor 1px, transparent 1px), linear-gradient(to bottom, currentColor 1px, transparent 1px)',
            backgroundSize: '44px 44px',
            maskImage: 'radial-gradient(ellipse 80% 60% at 50% 0%, #000 40%, transparent 100%)',
            WebkitMaskImage: 'radial-gradient(ellipse 80% 60% at 50% 0%, #000 40%, transparent 100%)',
          }}
        />
        <div className="absolute -top-40 left-1/2 h-[480px] w-[720px] -translate-x-1/2 rounded-full bg-gradient-to-r from-blue-500/25 via-violet-500/25 to-fuchsia-500/20 blur-3xl dark:from-blue-600/30 dark:via-violet-600/30 dark:to-fuchsia-600/20" />
        <div className="absolute right-[-10%] top-1/3 h-72 w-72 rounded-full bg-cyan-400/15 blur-3xl dark:bg-cyan-500/10" />
      </div>

      <Container className="grid items-center gap-14 pb-20 pt-14 sm:pt-20 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)] lg:gap-16 lg:pb-28 lg:pt-24">
        <div className="min-w-0">
          <p className="inline-flex max-w-full items-center gap-2 rounded-full border border-violet-500/25 bg-violet-500/10 px-3 py-1 text-xs font-medium text-violet-700 sm:text-sm dark:text-violet-300">
            <Sparkles className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="truncate">Free scam checker for links, SMS, emails &amp; files</span>
          </p>

          <h1
            id="hero-title"
            className="mt-6 text-balance font-display text-4xl leading-[1.08] text-foreground sm:text-5xl lg:text-6xl"
          >
            Got a suspicious link?{' '}
            <span className={gradientText}>Check it before you click.</span>
          </h1>

          <p className="mt-5 max-w-xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            PhishGuard spots fake bank, UPI, delivery and KYC scams in seconds — and tells you in plain language
            whether it&apos;s safe and exactly what to do next.
          </p>

          <div className="mt-8 max-w-xl">
            <QuickCheckForm />
          </div>

          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/scan?type=message" className={secondaryButton}>
              <MessageSquare className="h-4 w-4 text-violet-600 dark:text-violet-400" aria-hidden="true" />
              Check an SMS
            </Link>
            <Link href="/scan?type=email" className={secondaryButton}>
              <Mail className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
              Check an email
            </Link>
          </div>

          <ul className="mt-8 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted-foreground" aria-label="Why it's easy to try">
            {TRUST.map((item) => (
              <li key={item} className="inline-flex items-center gap-1.5">
                <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                {item}
              </li>
            ))}
          </ul>
        </div>

        <Reveal className="mx-auto w-full max-w-md lg:max-w-none">
          <ExampleResultCard />
        </Reveal>
      </Container>
    </section>
  )
}
