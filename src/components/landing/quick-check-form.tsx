'use client'

import { useRef, useState, useTransition, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { ArrowRight, Link2, Loader2 } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { focusRing, primaryButton } from './primitives'

const EXAMPLE_URL = 'paypa1-secure-login.xyz/verify'

export function QuickCheckForm() {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const [value, setValue] = useState('')
  const [isPending, startTransition] = useTransition()

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const url = value.trim()
    if (!url) {
      inputRef.current?.focus()
      return
    }
    startTransition(() => {
      router.push(`/scan?url=${encodeURIComponent(url)}`)
    })
  }

  return (
    <div>
      <form
        onSubmit={onSubmit}
        role="search"
        aria-label="Quick link check"
        className="rounded-2xl border border-border bg-card/80 p-2 shadow-xl shadow-violet-600/5 backdrop-blur-xl dark:border-white/10 dark:bg-white/[0.04] dark:shadow-black/40"
      >
        <div className="flex flex-col gap-2 sm:flex-row">
          <label htmlFor="quick-check-url" className="sr-only">
            Link to check
          </label>
          <div className="relative min-w-0 flex-1">
            <Link2
              className="pointer-events-none absolute left-3.5 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <input
              ref={inputRef}
              id="quick-check-url"
              name="url"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              placeholder="Paste a suspicious link…"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              aria-describedby="quick-check-hint"
              className="h-12 w-full min-w-0 rounded-xl border border-transparent bg-transparent pl-11 pr-3 font-mono text-[15px] text-foreground placeholder:font-sans placeholder:text-muted-foreground focus-visible:border-violet-500/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
            />
          </div>
          <button type="submit" disabled={isPending} className={cn(primaryButton, 'h-12 sm:px-6')}>
            {isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            )}
            {isPending ? 'Opening scanner…' : 'Check link'}
          </button>
        </div>
      </form>
      <p id="quick-check-hint" className="mt-3 text-sm text-muted-foreground">
        Opens the scanner and checks it straight away.{' '}
        <button
          type="button"
          onClick={() => {
            setValue(EXAMPLE_URL)
            inputRef.current?.focus()
          }}
          className={cn(
            'rounded font-medium text-violet-700 underline-offset-4 hover:underline dark:text-violet-300',
            focusRing,
          )}
        >
          Try an example
        </button>
      </p>
    </div>
  )
}
