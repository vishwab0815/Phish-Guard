import Link from 'next/link'
import type { LucideIcon } from 'lucide-react'
import { ArrowRight, Bot, Check, FileWarning, Link2, Mail, MessageSquare } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { Reveal } from './reveal'
import { Container, SectionHeading, focusRing, surfaceCard } from './primitives'

type Feature = {
  title: string
  summary: string
  bullets: string[]
  href: string
  cta: string
  icon: LucideIcon
  /** Tailwind classes for the icon tile */
  tone: string
}

const FEATURES: Feature[] = [
  {
    title: 'Links',
    summary: 'Spot fake bank, payment and delivery sites before you open them.',
    bullets: [
      'Lookalike and brand-impersonation checks, including SBI, HDFC, ICICI, Paytm, PhonePe, IRCTC, India Post and Aadhaar/UIDAI',
      'Catches typosquats like “paypa1” and Unicode look-alike letters',
      'Real domain registration age via RDAP — brand-new domains are a red flag',
      'Certificate check, plus Google Safe Browsing and VirusTotal (60–90 antivirus engines)',
    ],
    href: '/scan?type=url',
    cta: 'Check a link',
    icon: Link2,
    tone: 'from-blue-500/15 to-blue-500/5 text-blue-600 dark:text-blue-400 ring-blue-500/20',
  },
  {
    title: 'Emails',
    summary: 'Paste the whole email — we read the headers, sender and every link.',
    bullets: [
      'Sender spoofing, like “SBI Bank” writing from a gmail.com address',
      'Reply-To redirection and lookalike sender domains',
      'SPF, DKIM and DMARC results read from the headers',
      'Every link inside is checked, plus scam language',
    ],
    href: '/scan?type=email',
    cta: 'Check an email',
    icon: Mail,
    tone: 'from-violet-500/15 to-violet-500/5 text-violet-600 dark:text-violet-400 ring-violet-500/20',
  },
  {
    title: 'SMS & WhatsApp',
    summary: 'Recognises the scam messages Indians receive most.',
    bullets: [
      'KYC expiry, electricity disconnection and parcel/customs-held scams',
      '“Digital arrest”, task/job and lottery scams',
      'Flags any request for your OTP or UPI PIN',
      'AI analysis on top of the pattern checks',
    ],
    href: '/scan?type=message',
    cta: 'Check a message',
    icon: MessageSquare,
    tone: 'from-fuchsia-500/15 to-fuchsia-500/5 text-fuchsia-600 dark:text-fuchsia-400 ring-fuchsia-500/20',
  },
  {
    title: 'Files',
    summary: 'Check attachments and APKs before you open or install them.',
    bullets: [
      'Disguised executables like invoice.pdf.exe',
      'Office macros and risky scripts',
      'Android APKs and risky permissions (read SMS, accessibility)',
      'VirusTotal hash lookup — your file is never uploaded to VirusTotal',
    ],
    href: '/scan?type=file',
    cta: 'Check a file',
    icon: FileWarning,
    tone: 'from-amber-500/15 to-amber-500/5 text-amber-600 dark:text-amber-400 ring-amber-500/20',
  },
]

function IconTile({ icon: Icon, tone }: { icon: LucideIcon; tone: string }) {
  return (
    <span
      className={cn(
        'flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br ring-1 ring-inset',
        tone,
      )}
    >
      <Icon className="h-5 w-5" aria-hidden="true" />
    </span>
  )
}

function CardLink({ href, children }: { href: string; children: string }) {
  return (
    <Link
      href={href}
      className={cn(
        'group/link inline-flex items-center gap-1.5 rounded-md text-sm font-semibold text-violet-700 dark:text-violet-300',
        focusRing,
      )}
    >
      {children}
      <ArrowRight
        className="h-4 w-4 transition-transform group-hover/link:translate-x-0.5"
        aria-hidden="true"
      />
    </Link>
  )
}

export function Features() {
  return (
    <section id="features" aria-labelledby="features-title" className="scroll-mt-20 py-20 sm:py-28">
      <Container>
        <SectionHeading
          id="features-title"
          eyebrow="What PhishGuard checks"
          title="One place to check anything that feels off"
          description="Every scan runs several independent checks and explains the result in plain words — no jargon, no guesswork."
        />

        <ul className="mt-14 grid gap-5 md:grid-cols-2">
          {FEATURES.map((f, i) => (
            <li key={f.title} className="min-w-0">
              <Reveal delay={(i % 2) * 0.08} className="h-full">
                <article
                  className={cn(
                    surfaceCard,
                    'group flex h-full flex-col p-6 transition-colors hover:border-violet-500/30 sm:p-7 dark:hover:border-violet-400/30',
                  )}
                >
                  <div className="flex items-start gap-4">
                    <IconTile icon={f.icon} tone={f.tone} />
                    <div className="min-w-0">
                      <h3 className="text-xl text-foreground">{f.title}</h3>
                      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{f.summary}</p>
                    </div>
                  </div>
                  <ul className="mt-5 flex-1 space-y-2.5">
                    {f.bullets.map((b) => (
                      <li key={b} className="flex gap-2.5 text-sm leading-relaxed text-foreground/85">
                        <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                        <span>{b}</span>
                      </li>
                    ))}
                  </ul>
                  <div className="mt-6 border-t border-border pt-4 dark:border-white/10">
                    <CardLink href={f.href}>{f.cta}</CardLink>
                  </div>
                </article>
              </Reveal>
            </li>
          ))}

          <li className="min-w-0 md:col-span-2">
            <Reveal className="h-full">
              <article className="relative isolate overflow-hidden rounded-2xl border border-violet-500/25 bg-gradient-to-br from-violet-500/10 via-card/70 to-blue-500/10 p-6 shadow-sm sm:p-8 dark:from-violet-500/15 dark:via-white/[0.02] dark:to-blue-500/10">
                <div
                  aria-hidden="true"
                  className="absolute -right-20 -top-20 -z-10 h-64 w-64 rounded-full bg-violet-500/20 blur-3xl"
                />
                <div className="grid gap-8 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] md:items-center">
                  <div className="min-w-0">
                    <div className="flex items-start gap-4">
                      <IconTile
                        icon={Bot}
                        tone="from-violet-500/20 to-blue-500/10 text-violet-600 dark:text-violet-300 ring-violet-500/30"
                      />
                      <div className="min-w-0">
                        <h3 className="text-xl text-foreground">AI safety assistant</h3>
                        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                          Not sure what you&apos;re looking at? Ask in your own words.
                        </p>
                      </div>
                    </div>
                    <ul className="mt-5 space-y-2.5">
                      {[
                        'Answers questions about scams in plain language',
                        'Slash commands run the real scanners right from the chat',
                        'Powered by a Groq-hosted AI model',
                      ].map((b) => (
                        <li key={b} className="flex gap-2.5 text-sm leading-relaxed text-foreground/85">
                          <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                          <span>{b}</span>
                        </li>
                      ))}
                    </ul>
                    <div className="mt-6">
                      <CardLink href="/scan?tab=assistant">Ask the assistant</CardLink>
                    </div>
                  </div>

                  {/* Illustrative chat bubbles (decorative) */}
                  <div aria-hidden="true" className="min-w-0 space-y-3">
                    <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Example conversation
                    </p>
                    <div className="ml-auto w-fit max-w-[90%] rounded-2xl rounded-br-md bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2.5 text-sm text-white shadow-md">
                      Someone on a video call says I&apos;m under “digital arrest” and must pay. Is this real?
                    </div>
                    <div className="w-fit max-w-[90%] rounded-2xl rounded-bl-md border border-border bg-card px-4 py-2.5 text-sm text-foreground shadow-sm dark:border-white/10 dark:bg-slate-900/80">
                      No — it&apos;s a scam. There&apos;s no such thing as a “digital arrest”. Hang up, don&apos;t pay,
                      and call <span className="font-semibold">1930</span> if you&apos;ve already sent money.
                    </div>
                  </div>
                </div>
              </article>
            </Reveal>
          </li>
        </ul>
      </Container>
    </section>
  )
}
