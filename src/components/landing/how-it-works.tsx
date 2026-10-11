import { CalendarClock, ClipboardPaste, Database, Fingerprint, Lock, ScanSearch, ShieldCheck } from 'lucide-react'
import { Reveal } from './reveal'
import { Container, SectionHeading, surfaceCard } from './primitives'
import { cn } from '@/components/ui/utils'

const STEPS = [
  {
    icon: ClipboardPaste,
    title: 'Paste it',
    body: 'A link, an SMS or WhatsApp message, a full email, or a file. No sign-up, no app to install.',
  },
  {
    icon: ScanSearch,
    title: 'Layered checks run in seconds',
    body: 'Pattern checks, domain age, certificate and threat-database lookups run side by side.',
  },
  {
    icon: ShieldCheck,
    title: 'Get a plain verdict and what to do',
    body: 'A clear risk level, the reasons behind it, and the exact next steps — in everyday language.',
  },
] as const

const LAYERS = [
  {
    icon: Fingerprint,
    title: 'Link pattern checks',
    detail: 'Lookalike brands, typosquats, Unicode tricks, javascript:/data: links',
  },
  {
    icon: CalendarClock,
    title: 'Domain age',
    detail: 'Real registration date via RDAP — new domains are a red flag',
  },
  {
    icon: Lock,
    title: 'Certificate',
    detail: 'TLS certificate validity for the site',
  },
  {
    icon: Database,
    title: 'Threat databases',
    detail: 'Google Safe Browsing and VirusTotal reputation',
  },
] as const

export function HowItWorks() {
  return (
    <section
      id="how-it-works"
      aria-labelledby="how-title"
      className="relative scroll-mt-20 border-y border-border/60 bg-muted/30 py-20 sm:py-28 dark:border-white/5 dark:bg-white/[0.015]"
    >
      <Container>
        <SectionHeading
          id="how-title"
          eyebrow="How it works"
          title="From “is this real?” to a clear answer"
          description="Three steps. No account, and nothing is kept on our servers — your scan history stays in your own browser."
        />

        <div className="mt-14 grid gap-10 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)] lg:gap-14">
          <ol className="relative space-y-4">
            {STEPS.map((step, i) => (
              <li key={step.title}>
                <Reveal delay={i * 0.08}>
                  <div className={cn(surfaceCard, 'flex gap-5 p-5 sm:p-6')}>
                    <div className="flex flex-col items-center">
                      <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-blue-600 to-violet-600 text-white shadow-md shadow-violet-600/25">
                        <step.icon className="h-5 w-5" aria-hidden="true" />
                      </span>
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold uppercase tracking-wider text-violet-600 dark:text-violet-400">
                        Step {i + 1}
                      </p>
                      <h3 className="mt-1 text-lg text-foreground sm:text-xl">{step.title}</h3>
                      <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground sm:text-base">{step.body}</p>
                    </div>
                  </div>
                </Reveal>
              </li>
            ))}
          </ol>

          <Reveal delay={0.1}>
            <div className={cn(surfaceCard, 'p-6 sm:p-7')}>
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-lg text-foreground">What a link check looks at</h3>
                <span className="rounded-full bg-violet-500/10 px-2.5 py-1 text-xs font-medium text-violet-700 dark:text-violet-300">
                  4 layers
                </span>
              </div>
              <div className="relative mt-6">
                <span
                  aria-hidden="true"
                  className="absolute bottom-3 left-[19px] top-3 w-px bg-gradient-to-b from-blue-500/50 via-violet-500/50 to-fuchsia-500/40"
                />
                <ol className="relative space-y-5">
                {LAYERS.map((layer) => (
                  <li key={layer.title} className="relative flex gap-4">
                    <span className="relative z-10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-border bg-background text-violet-600 shadow-sm dark:border-white/10 dark:bg-slate-950 dark:text-violet-400">
                      <layer.icon className="h-4 w-4" aria-hidden="true" />
                    </span>
                    <div className="min-w-0 pt-1">
                      <p className="font-semibold text-foreground">{layer.title}</p>
                      <p className="mt-0.5 text-sm leading-relaxed text-muted-foreground">{layer.detail}</p>
                    </div>
                  </li>
                ))}
                </ol>
              </div>
              <p className="mt-6 rounded-lg bg-muted/60 px-3 py-2 text-xs leading-relaxed text-muted-foreground dark:bg-white/[0.04]">
                Internal-network addresses are blocked, so the scanner can&apos;t be pointed at private systems.
              </p>
            </div>
          </Reveal>
        </div>
      </Container>
    </section>
  )
}
