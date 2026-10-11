# PhishGuard Documentation

This document is a short guide to the project structure and the main pieces that make PhishGuard work.

## Project Overview

PhishGuard v2.1.0 is an AI-assisted phishing detection platform. It analyzes suspicious URLs, emails, messages, and files, then combines those results with domain intelligence, SSL checks, IP reputation, and external threat feeds.

The goal is to give users a single place to inspect threats, review past scans, and get security guidance through the built-in AI assistant.

## Tech Stack

- Next.js 16 with the App Router
- React 19 and TypeScript
- Tailwind CSS and Framer Motion for UI
- Drizzle ORM with PostgreSQL
- Groq via groq-sdk (model set in src/lib/llm.ts) for the AI assistant and message analysis
- Radix UI, Lucide React, and Sonner for interface components

## How the App Is Organized

- src/app: Page routes and API endpoints
- src/components: Dashboard, scan UI, history, settings, and chatbot
- src/services: Detection logic and external intelligence providers
- src/db: Schema definitions, seed data, and database setup

## Main Detection Flow

1. A user submits a URL, email, message, or file.
2. The relevant API route forwards the request to the detection services.
3. Static analysis and intelligence layers generate indicators and risk scores.
4. Results are saved to the database and displayed in the dashboard or history views.
5. The AI chat endpoint can explain results or answer security questions.

## Local Setup

```bash
npm install
npm run db:push
npm run db:seed
npm run dev
```

Set DATABASE_URL in .env.local before running database commands. Optional AI and threat-intelligence keys can also be added there.

## Useful Files

- src/app/page.tsx: main application shell
- src/components/ScanInterface.tsx + src/components/scan/: scan forms, progress and result report
- src/components/Dashboard.tsx: summary metrics and recent activity
- src/components/AIChatbot.tsx: assistant UI for prompts and commands
- src/services/detection/masterDetector.ts: orchestration layer for URL scans

## Version

- Current project version: v2.1.0

## Notes

- External APIs are optional: without keys, scans use local analysis and say which checks were skipped.
- The UI and backend use the same scan data model so results stay consistent across views.
