import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { ExternalLink, Flag, KeyRound, PhoneCall, QrCode, Siren, Video } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { Reveal } from './reveal'
import { Container, SectionHeading, focusRing, surfaceCard } from './primitives'

type Fact = { icon: LucideIcon; title: string; body: ReactNode }

const externalLink = cn(
  'inline-flex items-center gap-1 rounded font-semibold text-violet-700 underline decoration-violet-500/40 underline-offset-4 hover:decoration-violet-500 dark:text-violet-300',
  focusRing,
)

const FACTS: Fact[] = [
  {
    icon: QrCode,
    title: 'You never need a QR code or UPI PIN to receive money',
    body: 'Scanning a QR code or entering your UPI PIN only ever sends money. Anyone asking you to do either to “receive” a payment is scamming you.',
  },
  {
    icon: Video,
    title: 'There is no such thing as a “digital arrest”',
    body: 'Police, CBI, customs or courts never arrest anyone or demand money over a video call. Hang up and don’t pay.',
  },
  {
    icon: KeyRound,
    title: 'Banks never ask for your OTP, PIN or CVV',
    body: 'Not by call, SMS, email or WhatsApp. Anyone asking for them is not your bank, whatever caller ID or logo they show.',
  },
  {
    icon: Flag,
    title: 'Report fraud calls and SMS on Chakshu',
    body: (
      <>
        Use the Chakshu facility on{' '}
        <a href="https://sancharsaathi.gov.in" target="_blank" rel="noopener noreferrer" className={externalLink}>
          Sanchar Saathi
          <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="sr-only">(opens in a new tab)</span>
        </a>{' '}
        to report suspected fraud calls, SMS and WhatsApp messages.
      </>
    ),
  },
]

export function StaySafe() {
  return (
    <section id="stay-safe" aria-labelledby="stay-safe-title" className="scroll-mt-20 py-20 sm:py-28">
      <Container>
        <SectionHeading
          id="stay-safe-title"
          eyebrow="Stay safe in India"
          title="Five facts that stop most scams"
          description="Scammers rely on urgency and fear. These rules hold every time — share them with your family."
        />

        <div className="mt-14 grid gap-5 lg:grid-cols-3">
          <Reveal className="lg:row-span-2">
            <aside
              aria-labelledby="helpline-title"
              className="relative isolate flex h-full flex-col overflow-hidden rounded-2xl border border-red-500/30 bg-gradient-to-br from-red-50 via-orange-50 to-amber-50 p-6 shadow-sm sm:p-8 dark:from-red-950/60 dark:via-red-950/30 dark:to-orange-950/30"
            >
              <div
                aria-hidden="true"
                className="absolute -right-16 -top-16 -z-10 h-56 w-56 rounded-full bg-red-500/20 blur-3xl"
              />
              <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-600 text-white shadow-lg shadow-red-600/30">
                <Siren className="h-6 w-6" aria-hidden="true" />
              </span>
              <h3 id="helpline-title" className="mt-5 text-2xl text-red-950 sm:text-3xl dark:text-red-50">
                Lost money? Call <span className="whitespace-nowrap">1930</span> now.
              </h3>
              <p className="mt-3 leading-relaxed text-red-900/80 dark:text-red-100/80">
                1930 is India&apos;s National Cyber Crime Helpline. Call immediately — acting fast matters. Then
                file a complaint at cybercrime.gov.in.
              </p>
              <div className="mt-auto flex flex-col gap-3 pt-8 sm:flex-row lg:flex-col">
                <a
                  href="tel:1930"
                  className={cn(
                    'inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-red-600 px-5 text-base font-semibold text-white shadow-lg shadow-red-600/25 transition-colors hover:bg-red-700',
                    focusRing,
                  )}
                >
                  <PhoneCall className="h-5 w-5" aria-hidden="true" />
                  Call 1930
                </a>
                <a
                  href="https://cybercrime.gov.in"
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    'inline-flex h-12 items-center justify-center gap-2 rounded-xl border border-red-600/30 bg-white/70 px-5 text-sm font-semibold text-red-800 transition-colors hover:bg-white dark:bg-white/5 dark:text-red-100 dark:hover:bg-white/10',
                    focusRing,
                  )}
                >
                  Report at cybercrime.gov.in
                  <ExternalLink className="h-4 w-4" aria-hidden="true" />
                  <span className="sr-only">(opens in a new tab)</span>
                </a>
              </div>
            </aside>
          </Reveal>

          <ul className="grid gap-5 sm:grid-cols-2 lg:col-span-2 lg:row-span-2">
            {FACTS.map((fact, i) => (
              <li key={fact.title} className="min-w-0">
                <Reveal delay={(i % 2) * 0.08} className="h-full">
                  <article className={cn(surfaceCard, 'h-full p-6')}>
                    <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-violet-500/10 text-violet-600 ring-1 ring-inset ring-violet-500/20 dark:text-violet-400">
                      <fact.icon className="h-5 w-5" aria-hidden="true" />
                    </span>
                    <h3 className="mt-4 text-lg leading-snug text-foreground">{fact.title}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{fact.body}</p>
                  </article>
                </Reveal>
              </li>
            ))}
          </ul>
        </div>
      </Container>
    </section>
  )
}
