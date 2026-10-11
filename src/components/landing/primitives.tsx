import type { ReactNode } from 'react'
import { CircleCheck, TriangleAlert } from 'lucide-react'
import { cn } from '@/components/ui/utils'

/** Shared visible focus style for links/buttons on the landing page. */
export const focusRing =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background'

export const primaryButton = cn(
  'security-button inline-flex h-11 items-center justify-center gap-2 rounded-xl px-5 text-sm font-semibold text-white',
  'bg-gradient-to-r from-blue-600 to-violet-600 shadow-lg shadow-violet-600/25 hover:from-blue-500 hover:to-violet-500',
  'disabled:cursor-not-allowed disabled:opacity-60',
  focusRing,
)

export const secondaryButton = cn(
  'inline-flex h-11 items-center justify-center gap-2 rounded-xl border border-border bg-background/60 px-4 text-sm font-medium text-foreground backdrop-blur',
  'transition-colors hover:border-violet-500/40 hover:bg-muted dark:bg-white/[0.03] dark:hover:bg-white/[0.07]',
  focusRing,
)

export const surfaceCard =
  'rounded-2xl border border-border bg-card/70 shadow-sm backdrop-blur-sm dark:border-white/10 dark:bg-white/[0.03]'

export const gradientText =
  'bg-gradient-to-r from-blue-600 via-violet-600 to-fuchsia-600 bg-clip-text text-transparent dark:from-blue-400 dark:via-violet-400 dark:to-fuchsia-400'

export function Container({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('mx-auto w-full max-w-6xl px-4 sm:px-6 lg:px-8', className)}>{children}</div>
}

export function SectionHeading({
  id,
  eyebrow,
  title,
  description,
  align = 'center',
}: {
  id: string
  eyebrow: string
  title: ReactNode
  description?: ReactNode
  align?: 'center' | 'left'
}) {
  return (
    <div className={cn('max-w-2xl', align === 'center' && 'mx-auto text-center')}>
      <p className="text-sm font-semibold uppercase tracking-[0.18em] text-violet-600 dark:text-violet-400">
        {eyebrow}
      </p>
      <h2 id={id} className="mt-3 text-balance text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
        {title}
      </h2>
      {description ? (
        <p className="mt-4 text-pretty text-base leading-relaxed text-muted-foreground sm:text-lg">{description}</p>
      ) : null}
    </div>
  )
}

export type Verdict = 'critical' | 'safe'

/** Verdict pill: always icon + text so colour is never the only signal. */
export function VerdictBadge({ verdict, className }: { verdict: Verdict; className?: string }) {
  const critical = verdict === 'critical'
  const Icon = critical ? TriangleAlert : CircleCheck
  return (
    <span
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold',
        critical
          ? 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300'
          : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
        className,
      )}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {critical ? 'Critical' : 'Safe'}
    </span>
  )
}
