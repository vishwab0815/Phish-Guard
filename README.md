# Cyber-Protect (PhishGuard) 🛡️

> AI-Powered Phishing Detection Platform - Protecting users from cyber threats with intelligent, multi-layered analysis.

**Modern | Type-Safe | Production-Ready**

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Set up environment
cp .env.example .env.local
# Edit .env.local with your Supabase DATABASE_URL

# 3. Initialize database
npm run db:push
npm run db:seed

# 4. Start developing
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) ✅

---

## ✨ Key Features

- ✅ **Multi-Layer Detection**: 5+ detection layers (Static → Domain → SSL → IP → AI Analysis).
- ✅ **Cloud Intelligence**: Direct integration with **VirusTotal**, **Google Safe Browsing**, and **PhishTank**.
- ✅ **Groq AI powered**: High-fidelity security chatbot and message classifier using **Llama 3.3 (70B)**.
- ✅ **Modern Tech**: Built with **Next.js 15**, **Drizzle ORM (Supabase)**, and **Framer Motion**.
- ✅ **Premium UI**: Glassmorphism design system with Liquid-smooth animations.
- ✅ **Enterprise Ready**: Full test suite, production build verified, and comprehensive health monitoring.

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| **[docs/README.md](docs/README.md)** | 📖 **Beginner's Master Guide** (Start here!) |

---

## 🛠️ Tech Stack

**Frontend**: Next.js 16 • React 19 • TypeScript 5.7 • Tailwind CSS • Framer Motion

**Backend**: Node.js • Drizzle ORM • PostgreSQL (Supabase) • Jest

**Infrastructure**: Layered Service Architecture • Orchestrator Pattern

---

## 📦 Core Commands

```bash
# Development
npm run dev             # Start dev server
npm run build           # Production build
npm run start           # Production start
npm run lint            # Linting check

# Database (Drizzle)
npm run db:push         # Push schema to Supabase
npm run db:studio       # Interactive DB manager
npm run db:seed         # Seed initial models/data

# Testing
npm test                # Run all tests
npm run test:coverage   # Coverage report
```

---

## 🔐 Security & Performance

- **Safety**: fully sanitized inputs and parameterized database queries.
- **Control**: Comprehensive rate limiting on all analysis endpoints.
- **Speed**: Optimized database indexing and edge-ready API routes.

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

*Last Updated: March 2026 | Status: ✅ Production Ready*
