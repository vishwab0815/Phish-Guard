import Link from 'next/link'
import { ArrowRight, Bot } from 'lucide-react'
import { cn } from '@/components/ui/utils'
import { Reveal } from './reveal'
import { Container } from './primitives'

export function FinalCta() {
  return (
    <section aria-labelledby="cta-title" className="pb-20 sm:pb-28">
      <Container>
        <Reveal>
          <div className="relative isolate overflow-hidden rounded-3xl bg-gradient-to-br from-blue-700 via-violet-700 to-fuchsia-700 px-6 py-14 text-center shadow-2xl shadow-violet-900/20 sm:px-12 sm:py-20">
            <div
              aria-hidden="true"
              className="absolute inset-0 -z-10 text-white/[0.07]"
              style={{
                backgroundImage:
                  'linear-gradient(to right, currentColor 1px, transparent 1px), linear-gradient(to bottom, currentColor 1px, transparent 1px)',
                backgroundSize: '36px 36px',
                maskImage: 'radial-gradient(ellipse at center, #000 30%, transparent 75%)',
                WebkitMaskImage: 'radial-gradient(ellipse at center, #000 30%, transparent 75%)',
              }}
            />
            <div aria-hidden="true" className="absolute -left-24 -top-24 -z-10 h-72 w-72 rounded-full bg-cyan-400/30 blur-3xl" />
            <div aria-hidden="true" className="absolute -bottom-24 -right-24 -z-10 h-72 w-72 rounded-full bg-fuchsia-400/30 blur-3xl" />

            <h2 id="cta-title" className="mx-auto max-w-2xl text-balance text-3xl text-white sm:text-4xl">
              Not sure about a message? Check it now.
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-base leading-relaxed text-white/85 sm:text-lg">
              It takes seconds, it&apos;s free, and you don&apos;t need an account.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Link
                href="/scan"
                className={cn(
                  'inline-flex h-12 w-full items-center justify-center gap-2 rounded-xl bg-white px-6 text-sm font-semibold text-violet-800 shadow-lg transition-colors hover:bg-violet-50 sm:w-auto',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-violet-700',
                )}
              >
                Open scanner
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
              <Link
                href="/scan?tab=assistant"
                className={cn(
                  'inline-flex h-12 w-full items-center justify-center gap-2 rounded-xl border border-white/30 bg-white/10 px-6 text-sm font-semibold text-white backdrop-blur transition-colors hover:bg-white/20 sm:w-auto',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-violet-700',
                )}
              >
                <Bot className="h-4 w-4" aria-hidden="true" />
                Ask the AI assistant
              </Link>
            </div>
          </div>
        </Reveal>
      </Container>
    </section>
  )
}
