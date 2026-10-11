'use client'

import { useSyncExternalStore } from 'react'
import { useTheme } from 'next-themes'
import { Moon, Sun } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { focusRing } from './primitives'

const noopSubscribe = () => () => {}

/** true after hydration on the client; false during SSR. */
function useMounted() {
  return useSyncExternalStore(noopSubscribe, () => true, () => false)
}

export function ThemeToggle({ className }: { className?: string }) {
  const { resolvedTheme, setTheme } = useTheme()
  const mounted = useMounted()
  const isDark = resolvedTheme === 'dark'

  return (
    <button
      type="button"
      onClick={() => setTheme(isDark ? 'light' : 'dark')}
      aria-label={mounted ? (isDark ? 'Switch to light theme' : 'Switch to dark theme') : 'Toggle theme'}
      className={cn(
        'inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-background/60 text-foreground transition-colors hover:bg-muted dark:bg-white/[0.03] dark:hover:bg-white/[0.08]',
        focusRing,
        className,
      )}
    >
      {mounted ? (
        isDark ? (
          <Sun className="h-4 w-4 text-amber-400" aria-hidden="true" />
        ) : (
          <Moon className="h-4 w-4 text-blue-600" aria-hidden="true" />
        )
      ) : (
        <span className="h-4 w-4" aria-hidden="true" />
      )}
    </button>
  )
}
