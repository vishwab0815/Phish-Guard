'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowRight, Menu, Shield, X } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { ThemeToggle } from './theme-toggle'
import { Container, focusRing } from './primitives'

const NAV_LINKS = [
  { href: '#features', label: 'Features' },
  { href: '#how-it-works', label: 'How it works' },
  { href: '#stay-safe', label: 'Stay safe' },
] as const

export function SiteHeader() {
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  return (
    <header className="sticky top-0 z-50 border-b border-border/60 bg-background/75 backdrop-blur-xl supports-[backdrop-filter]:bg-background/60 dark:border-white/10">
      <Container className="flex h-16 items-center justify-between gap-3">
        <Link
          href="/"
          className={cn('flex shrink-0 items-center gap-2 rounded-lg', focusRing)}
          aria-label="PhishGuard home"
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-blue-600 to-violet-600 shadow-md shadow-violet-600/30">
            <Shield className="h-[18px] w-[18px] text-white" aria-hidden="true" />
          </span>
          <span className="font-display text-lg text-foreground">PhishGuard</span>
        </Link>

        <nav aria-label="Main" className="hidden md:block">
          <ul className="flex items-center gap-1">
            {NAV_LINKS.map((link) => (
              <li key={link.href}>
                <a
                  href={link.href}
                  className={cn(
                    'rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground',
                    focusRing,
                  )}
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <div className="flex items-center gap-2">
          <ThemeToggle />
          <button
            type="button"
            className={cn(
              'inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-background/60 text-foreground hover:bg-muted md:hidden dark:bg-white/[0.03]',
              focusRing,
            )}
            aria-label={open ? 'Close menu' : 'Open menu'}
            aria-expanded={open}
            aria-controls="mobile-nav"
            onClick={() => setOpen((v) => !v)}
          >
            {open ? <X className="h-4 w-4" aria-hidden="true" /> : <Menu className="h-4 w-4" aria-hidden="true" />}
          </button>
          <Link
            href="/scan"
            className={cn(
              'security-button inline-flex h-9 items-center gap-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-violet-600 px-3 text-sm font-semibold text-white shadow-md shadow-violet-600/25 hover:from-blue-500 hover:to-violet-500 sm:px-4',
              focusRing,
            )}
          >
            Open scanner
            <ArrowRight className="hidden h-4 w-4 sm:block" aria-hidden="true" />
          </Link>
        </div>
      </Container>

      {open ? (
        <nav id="mobile-nav" aria-label="Main mobile" className="border-t border-border/60 md:hidden dark:border-white/10">
          <Container className="py-2">
            <ul className="flex flex-col">
              {NAV_LINKS.map((link) => (
                <li key={link.href}>
                  <a
                    href={link.href}
                    onClick={() => setOpen(false)}
                    className={cn(
                      'block rounded-lg px-3 py-3 text-base font-medium text-foreground hover:bg-muted',
                      focusRing,
                    )}
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </Container>
        </nav>
      ) : null}
    </header>
  )
}
