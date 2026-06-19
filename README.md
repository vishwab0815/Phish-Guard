# PhishGuard v2.1.0

PhishGuard is an AI-assisted phishing detection and threat analysis platform built to inspect URLs, emails, files, and messages through layered security checks. It combines static analysis, domain intelligence, SSL validation, IP reputation, external threat feeds, and chat-based security guidance in one dashboard.

## What the project does

PhishGuard helps identify suspicious content before a user interacts with it. The app provides:

- URL, email, message, and file analysis
- Multi-layer threat scoring and risk breakdowns
- Scan history, dashboard metrics, and health checks
- AI security chat for security guidance and incident response
- External intelligence lookups through threat feeds and model-backed analysis

## Tech Stack

- Frontend: Next.js 16, React 19, TypeScript, Tailwind CSS, Framer Motion
- Backend: Next.js App Router API routes, Node.js
- Database: PostgreSQL with Drizzle ORM
- AI and Intelligence: Groq SDK, LangChain, external threat integrations
- UI Components: Radix UI, Lucide React, Sonner
- Testing: Jest, Testing Library, JSDOM

## Project Structure

- src/app: App Router pages and API routes
- src/components: Dashboard, scanner, history, settings, and AI chat UI
- src/services: Detection engines and external intelligence providers
- src/db: Schema, seed data, and database utilities
- docs: Beginner-friendly project guide and supporting documentation

## Getting Started

```bash
npm install
npm run db:push
npm run db:seed
npm run dev
```

Then open http://localhost:3000.

## Common Commands

```bash
npm run dev
npm run build
npm run start
npm run lint
npm run type-check
npm run db:studio
npm run db:seed
```

## Notes

- Use .env.local for DATABASE_URL and any optional AI or threat-intel API keys.
- The app is designed to fall back to local analysis when external services are unavailable.
- See [docs/README.md](docs/README.md) for a more guided walkthrough of the codebase.

## License

This project is open source and available under the MIT License.
