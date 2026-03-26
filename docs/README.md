# PhishGuard: Beginner's Master Guide 🎓

Welcome to PhishGuard! This guide is designed to help you understand what this project is, how it works, and how you can get started as a developer—even if you're new to cybersecurity.

---

## 🛡️ What is PhishGuard?

PhishGuard is an **automated cybersecurity analyst**. 

In the real world, attackers send "phishing" links to steal passwords. Usually, a human expert would have to look at a link to see if it's dangerous. PhishGuard does this automatically using multiple "layers" of intelligence:

1.  **Static Layer**: Does the link look weird? (e.g., `paypa1.com` instead of `paypal.com`)
2.  **Domain Layer**: How old is the website? (New sites are more suspicious)
3.  **Security Layer**: Does it have a valid security certificate (SSL)?
4.  **Intelligence Layer**: Do global blacklists already know about this threat?

---

## 🚀 Beginner's Quick Start

If you've never worked on a project like this before, follow these steps exactly:

### 1. The Environment (The Context)
The app needs to store its data somewhere. We use **Supabase** (a cloud database).
- Create a [Supabase](https://supabase.com) account.
- Get your **Connection String**.
- Put it in a file named `.env.local` as `DATABASE_URL`.

### 2. The Setup (The Foundations)
Run these commands in your terminal:
```bash
npm install          # Download the code's tools
npm run db:push      # Tell the database how to store our data
npm run db:seed      # Put some starting data (like AI models) into the database
npm run dev          # Start the app!
```

### 3. Your First Scan
Open [http://localhost:3000](http://localhost:3000), go to the **Scan Interface**, and type `https://www.google.com`. You'll see the engine working in real-time!

---

## 🏗️ Where is the Code? (Simplified Map)

If you want to start coding, here is where the important stuff lives:

- **The Visuals**: `src/app/page.tsx` (This is the main screen you see).
- **The Dashboard**: `src/components/Dashboard.tsx` (Controls the stats and charts).
- **The Brain**: `src/services/detection/masterDetector.ts` (Coordinates all scanning).
- **The Database**: `src/db/schema.ts` (Defines what a "User" or a "Scan" looks like).

---

## 🏗️ Architecture (The "Big Picture")

PhishGuard follows a **Layered Architecture**:
- **UI Layer** (Frontend): React components that users interact with.
- **Service Layer** (Backend): The engines that actually do the scanning.
- **Data Layer** (Database): Where we store history and settings.

The **MasterDetector** is the most important service—it calls all the others to give a final "Threat Level" (SAFE, WARNING, or DANGER).

---

## ❓ FAQ for Beginners

**"What is Drizzle?"**
It's our "Translator". It lets us talk to the database using JavaScript instead of complex SQL commands.

**"Do I need to pay for anything?"**
No! This project is designed to work for free using Supabase and Groq AI's free tiers.

**"Where do I ask for help?"**
Start by reading the code comments! Every major function has a description explaining *why* it exists.

---

*PhishGuard — Making the web safer, one scan at a time.* 🛡️
