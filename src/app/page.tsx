import { SiteHeader } from '@/components/landing/site-header'
import { Hero } from '@/components/landing/hero'
import { Features } from '@/components/landing/features'
import { HowItWorks } from '@/components/landing/how-it-works'
import { RealResults } from '@/components/landing/real-results'
import { StaySafe } from '@/components/landing/stay-safe'
import { FinalCta } from '@/components/landing/final-cta'
import { SiteFooter } from '@/components/landing/site-footer'

export default function LandingPage() {
  return (
    <div className="relative flex min-h-screen flex-col overflow-x-clip bg-background text-foreground">
      <a
        href="#main"
        className="sr-only z-[60] rounded-lg bg-background px-4 py-2 text-sm font-semibold text-foreground shadow-lg ring-2 ring-ring focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        Skip to content
      </a>
      <SiteHeader />
      <main id="main" className="flex-1">
        <Hero />
        <Features />
        <HowItWorks />
        <RealResults />
        <StaySafe />
        <FinalCta />
      </main>
      <SiteFooter />
    </div>
  )
}
