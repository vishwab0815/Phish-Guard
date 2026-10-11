import { CircleCheck, CircleX, Link2, ShieldAlert } from 'lucide-react'
import { VerdictBadge } from './primitives'

const REASONS = [
  'Pretends to be PayPal: a “1” replaces the “l” (typosquat)',
  'Ends in .xyz, a domain ending often abused by scammers',
  'Login-bait words in the link: “secure”, “login”, “verify”',
] as const

function RiskRing({ score }: { score: number }) {
  const r = 26
  const c = 2 * Math.PI * r
  return (
    <div className="relative h-16 w-16 shrink-0">
      <svg viewBox="0 0 64 64" className="h-16 w-16 -rotate-90" aria-hidden="true">
        <circle cx="32" cy="32" r={r} fill="none" strokeWidth="6" className="stroke-red-500/15" />
        <circle
          cx="32"
          cy="32"
          r={r}
          fill="none"
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - score / 100)}
          className="stroke-red-500"
        />
      </svg>
      <span className="absolute inset-0 flex flex-col items-center justify-center leading-none">
        <span className="font-display text-lg text-foreground">{score}</span>
        <span className="text-[10px] text-muted-foreground">/100</span>
      </span>
    </div>
  )
}

/** Static mock of a scanner result — clearly labelled as an example. */
export function ExampleResultCard() {
  return (
    <div className="relative">
      <div
        aria-hidden="true"
        className="absolute -inset-4 -z-10 rounded-[2rem] bg-gradient-to-br from-red-500/20 via-violet-500/20 to-blue-500/20 blur-2xl dark:from-red-500/25 dark:via-violet-500/25 dark:to-blue-500/25"
      />
      <figure
        aria-label="Example result for the link paypa1-secure-login.xyz/verify"
        className="relative overflow-hidden rounded-2xl border border-border bg-card/90 shadow-2xl shadow-slate-900/10 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/70 dark:shadow-black/50"
      >
        <div className="h-1 w-full bg-gradient-to-r from-red-500 via-orange-500 to-red-500" aria-hidden="true" />
        <div className="p-5 sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/60 px-2.5 py-1 text-xs font-medium text-muted-foreground dark:border-white/10 dark:bg-white/5">
              <span className="h-1.5 w-1.5 rounded-full bg-violet-500" aria-hidden="true" />
              Example result
            </span>
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
              Link scan
            </span>
          </div>

          <p className="mt-4 break-all rounded-lg border border-border bg-muted/50 px-3 py-2 font-mono text-sm text-foreground dark:border-white/10 dark:bg-white/[0.04]">
            paypa1-secure-login.xyz/verify
          </p>

          <div className="mt-5 flex items-center gap-4">
            <RiskRing score={100} />
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <VerdictBadge verdict="critical" />
                <span className="sr-only">Risk score 100 out of 100.</span>
              </div>
              <p className="mt-1.5 font-display text-lg leading-snug text-foreground">Don&apos;t open this link</p>
            </div>
          </div>

          <figcaption className="sr-only">
            The link is rated Critical because it imitates PayPal.
          </figcaption>

          <p className="mt-6 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Why</p>
          <ul className="mt-2 space-y-2">
            {REASONS.map((reason) => (
              <li key={reason} className="flex gap-2.5 text-sm leading-snug text-foreground/90">
                <CircleX className="mt-0.5 h-4 w-4 shrink-0 text-red-500" aria-hidden="true" />
                <span>{reason}</span>
              </li>
            ))}
          </ul>

          <div className="mt-5 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5">
            <p className="flex items-center gap-2 text-sm font-semibold text-amber-800 dark:text-amber-300">
              <ShieldAlert className="h-4 w-4" aria-hidden="true" />
              What to do now
            </p>
            <p className="mt-1 text-sm leading-relaxed text-amber-900/90 dark:text-amber-100/85">
              Don&apos;t enter any details. If you already typed your password, change it on the real PayPal site
              and turn on two-step login.
            </p>
          </div>
        </div>
      </figure>

      <div
        aria-hidden="true"
        className="absolute -bottom-6 -left-8 hidden items-center gap-2.5 rounded-xl border border-border bg-card/95 px-3.5 py-2.5 shadow-xl backdrop-blur-xl lg:flex dark:border-white/10 dark:bg-slate-900/90"
      >
        <CircleCheck className="h-5 w-5 text-emerald-500" />
        <div className="leading-tight">
          <p className="font-mono text-xs text-foreground">onlinesbi.sbi</p>
          <p className="text-[11px] text-muted-foreground">Real SBI site · Safe</p>
        </div>
      </div>
    </div>
  )
}
