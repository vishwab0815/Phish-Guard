import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Separator } from "./ui/separator";
import { AlertTriangle, Brain, Lightbulb, Loader2, MessageSquare, Send, Terminal, User } from "lucide-react";
import {
  BackendService,
  errorMessage,
  isAbortError,
  type ChatTurn,
  type DomainIntelResponse,
} from "@/utils/BackendService";
import { normalizeAnalysis } from "./scan/report";
import { INDIA_EMERGENCY_STEPS, THREAT_META, isDangerous, verdictSentence } from "./scan/threatLevel";
import { SimpleMarkdown } from "./SimpleMarkdown";

type MessageKind = "text" | "command" | "error" | "notice";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  kind: MessageKind;
  timestamp: Date;
  model?: string;
}

const WELCOME = `**Hi, I'm the PhishGuard assistant.**
Ask me anything about scams, phishing or staying safe online. You can also use these commands:
- \`/scan <link>\` — check a link with the PhishGuard scanner
- \`/analyze <text>\` — check a suspicious SMS or message
- \`/threat-intel <domain>\` — look up WHOIS/DNS and reputation records for a domain
- \`/incident-response\` — what to do if you've been scammed
- \`/help\` — all commands

I can make mistakes. For anything involving money, verify through official channels.`;

const HELP = `**Commands**
- \`/scan <link>\` — runs the real link scanner (same as the Scan tab)
- \`/analyze <text>\` — runs the real message scanner
- \`/threat-intel <domain>\` — WHOIS, DNS and reputation lookup for a domain
- \`/security-tips\` — practical habits that stop most scams
- \`/phish-indicators\` — common warning signs to look for
- \`/incident-response\` — steps if you clicked, paid or shared details
- \`/report\` — where to report a scam in India

Anything else you type is answered by the AI model.`;

const SECURITY_TIPS = `**Practical habits that stop most scams**
1. Never share an OTP, UPI PIN, CVV or password — banks and government agencies never ask for them.
2. You never need to enter your UPI PIN to receive money. A "collect request" asking for your PIN is a scam.
3. Don't install screen-sharing or "support" apps (AnyDesk, TeamViewer, QuickSupport) because a caller asked you to.
4. Type the bank or company website yourself, or use its official app, instead of clicking links in SMS, email or WhatsApp.
5. Be suspicious of urgency: "account blocked today", "KYC expiring", "parcel held", "electricity cut tonight".
6. Turn on two-factor authentication for email, banking and social media.
7. Check unknown links and messages with the Scan tab before acting on them.`;

const PHISH_INDICATORS = `**Common warning signs**
- Pressure or threats: account suspension, legal action, "digital arrest", disconnection tonight
- Requests for OTP, PIN, CVV, passwords, Aadhaar/PAN photos or remote-access apps
- Links that don't match the real website (extra words, odd spellings, unusual endings like .xyz or .top, shortened links)
- Prizes, lotteries, refunds or job offers you didn't apply for — especially ones asking for a "fee" first
- Sender addresses or numbers that don't match the organisation, or generic greetings like "Dear customer"
- Unexpected attachments, especially .apk, .exe, .zip or Office files asking to "enable content"`;

const INCIDENT_RESPONSE = `**If you clicked a link, shared details or paid**
1. **Call 1930** (National Cyber Crime Helpline) immediately — the sooner you report, the better the chance of freezing the money.
2. File a complaint at **cybercrime.gov.in** and keep the acknowledgement number.
3. Call your bank on the number printed on your card or its official website. Block the card/UPI and dispute the transaction.
4. Change passwords for any account you entered on the fake page, starting with email, and turn on two-factor authentication.
5. If you installed an app because someone asked you to, uninstall it and disconnect from the internet until it's removed.
6. Keep evidence: screenshots, phone numbers, transaction IDs, links and email headers.`;

const REPORT_GUIDANCE = `**Reporting a scam in India**
- Report cyber fraud at **cybercrime.gov.in** or call **1930**.
- Report fraud calls/SMS/WhatsApp numbers on the **Sanchar Saathi "Chakshu"** portal (sancharsaathi.gov.in).
- Forward phishing emails to the impersonated company's official abuse/security address.

Domain blocking in PhishGuard is managed by administrators, so it isn't available from chat.`;

const QUICK_COMMANDS = ["/scan ", "/analyze ", "/threat-intel ", "/incident-response"];

const SUGGESTED_QUESTIONS = [
  "Someone asked for my OTP to cancel an order — what should I do?",
  "How do I spot a fake KYC update SMS?",
  "Is it safe to scan a QR code to receive money?",
  "What makes a link suspicious?",
];

function fmt(value: string | number | null | undefined, suffix = ""): string {
  if (value === null || value === undefined || value === "") return "Not available";
  return `${value}${suffix}`;
}

function yesNo(value: boolean | null | undefined): string {
  return typeof value === "boolean" ? (value ? "Yes" : "No") : "Not available";
}

function formatDomainIntel(domain: string, res: DomainIntelResponse): string {
  const d = res.domain_intelligence;
  if (!d) return `No intelligence was returned for \`${domain}\`.`;
  const whois = d.whois_data ?? null;
  const dns = d.dns_data ?? null;
  const rep = d.reputation ?? null;
  const created = whois?.createdDate ? new Date(whois.createdDate) : null;
  const lines = [
    `**Domain lookup: \`${d.domain ?? domain}\`**`,
    `- Risk score: ${fmt(d.risk_score, "/100")}`,
    `- On known phishing lists: ${yesNo(rep?.isKnownPhishing)}`,
    `- On known malware lists: ${yesNo(rep?.isKnownMalware)}`,
    `- Reports in PhishGuard's records: ${fmt(rep?.reportCount)}`,
    `- Registered: ${created && !Number.isNaN(created.getTime()) ? created.toLocaleDateString() : "Not available"}`,
    `- Domain age: ${fmt(whois?.domainAge, " days")}`,
    `- Registrar: ${fmt(whois?.registrar)}`,
    `- IP addresses: ${dns?.ipAddresses?.length ? dns.ipAddresses.slice(0, 5).join(", ") : "Not available"}`,
    `- Mail servers (MX): ${Array.isArray(dns?.mxRecords) ? dns.mxRecords.length : "Not available"}`,
  ];
  if (d.indicators?.length) {
    lines.push("", "**Findings**", ...d.indicators.map((i) => `- ${i}`));
  }
  lines.push("", "\"Not available\" means the lookup returned nothing for that field.");
  return lines.join("\n");
}

function extractDomain(input: string): string {
  const trimmed = input.trim();
  try {
    return new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`).hostname;
  } catch {
    return trimmed;
  }
}

export function AIChatbot() {
  const [messages, setMessages] = useState<Message[]>([
    { id: "welcome", role: "assistant", content: WELCOME, kind: "text", timestamp: new Date() },
  ]);
  const [inputMessage, setInputMessage] = useState("");
  const [isBusy, setIsBusy] = useState(false);
  const idRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const nextId = () => `m${++idRef.current}`;

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, isBusy]);

  useEffect(() => () => abortRef.current?.abort(), []);

  const runCommand = async (raw: string, signal: AbortSignal): Promise<{ content: string; kind: MessageKind }> => {
    const commandRaw = raw.split(/\s+/)[0];
    const command = commandRaw.toLowerCase();
    const arg = raw.slice(commandRaw.length).trim();

    switch (command) {
      case "/help":
        return { content: HELP, kind: "command" };
      case "/security-tips":
        return { content: SECURITY_TIPS, kind: "command" };
      case "/phish-indicators":
        return { content: PHISH_INDICATORS, kind: "command" };
      case "/incident-response":
        return { content: INCIDENT_RESPONSE, kind: "command" };
      case "/report":
      case "/block-domain":
        return { content: REPORT_GUIDANCE, kind: "command" };
      case "/scan":
      case "/analyze": {
        if (!arg) {
          return {
            content:
              command === "/scan"
                ? "Add a link after the command, e.g. `/scan https://example.com`"
                : "Add the message text after the command, e.g. `/analyze Your KYC expires today, click here`",
            kind: "error",
          };
        }
        const kind = command === "/scan" ? "url" : "message";
        const response =
          kind === "url" ? await BackendService.analyzeUrl(arg, signal) : await BackendService.analyzeMessage(arg, signal);
        const report = normalizeAnalysis(kind, response, arg);
        const lines = [
          `**Verdict: ${THREAT_META[report.level].label}**`,
          verdictSentence(report.level, report.kind),
          `Risk score: ${fmt(report.riskScore, "/100")} · Confidence: ${fmt(report.confidence, "%")}`,
        ];
        if (report.recommendations.length) {
          lines.push("", "**What to do**", ...report.recommendations.map((r) => `- ${r}`));
        }
        if (isDangerous(report.level)) {
          lines.push("", "**Already clicked, entered details or paid?**", ...INDIA_EMERGENCY_STEPS.map((s) => `- ${s}`));
        }
        if (report.indicators.length) {
          lines.push("", "**Findings**", ...report.indicators.map((i) => `- ${i}`));
        }
        return { content: lines.join("\n"), kind: "command" };
      }
      case "/threat-intel": {
        if (!arg) return { content: "Add a domain, e.g. `/threat-intel example.com`", kind: "error" };
        const domain = extractDomain(arg);
        const res = await BackendService.domainIntel(domain, signal);
        return { content: formatDomainIntel(domain, res), kind: "command" };
      }
      default:
        return { content: `Unknown command \`${command}\`. Type \`/help\` to see what's available.`, kind: "error" };
    }
  };

  const send = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isBusy) return;

    const userMessage: Message = { id: nextId(), role: "user", content: trimmed, kind: "text", timestamp: new Date() };
    const context: ChatTurn[] = messages
      .filter((m) => m.id !== "welcome" && m.kind !== "error")
      .slice(-6)
      .map((m) => ({ role: m.role, content: m.content }));

    setMessages((prev) => [...prev, userMessage]);
    setInputMessage("");
    setIsBusy(true);

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      let reply: Omit<Message, "id" | "role" | "timestamp">;
      if (trimmed.startsWith("/")) {
        reply = await runCommand(trimmed, controller.signal);
      } else {
        const res = await BackendService.chat(trimmed, context, controller.signal);
        if (!res.response || typeof res.response !== "string") throw new Error("The assistant returned an empty answer — try again.");
        reply = res.fallback
          ? {
              content: `${res.response}\n\n(The AI model isn't configured on this server, so this is a built-in answer.)`,
              kind: "notice",
            }
          : { content: res.response, kind: "text", model: res.model };
      }
      if (controller.signal.aborted) return;
      setMessages((prev) => [...prev, { id: nextId(), role: "assistant", timestamp: new Date(), ...reply }]);
    } catch (error) {
      if (isAbortError(error)) return;
      setMessages((prev) => [
        ...prev,
        {
          id: nextId(),
          role: "assistant",
          kind: "error",
          timestamp: new Date(),
          content: errorMessage(error, "Couldn't reach the assistant — try again."),
        },
      ]);
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setIsBusy(false);
        inputRef.current?.focus();
      }
    }
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    send(inputMessage);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") setInputMessage("");
  };

  const bubbleClass = (m: Message) => {
    if (m.role === "user") return "bg-primary text-primary-foreground";
    switch (m.kind) {
      case "command":
        return "bg-purple-50 dark:bg-purple-950/20 border-l-4 border-l-purple-500";
      case "error":
        return "bg-red-50 dark:bg-red-950/20 border-l-4 border-l-red-500";
      case "notice":
        return "bg-orange-50 dark:bg-orange-950/20 border-l-4 border-l-orange-500";
      default:
        return "bg-muted";
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="w-full max-w-full space-y-6"
    >
      <Card className="phish-card w-full">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-500" aria-hidden="true" />
            AI security assistant
          </CardTitle>
          <CardDescription>
            Answers come from an AI model (via Groq) when configured. Commands use the real PhishGuard scanners.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="border rounded-lg bg-muted/20 h-[28rem] flex flex-col">
            <div
              ref={scrollRef}
              className="flex-1 overflow-y-auto p-4 space-y-4"
              role="log"
              aria-live="polite"
              aria-label="Conversation"
            >
              {messages.map((message) => (
                <div key={message.id} className={`flex gap-3 ${message.role === "user" ? "flex-row-reverse" : "flex-row"}`}>
                  <div className="flex-shrink-0">
                    <div
                      className={`w-8 h-8 rounded-full flex items-center justify-center ${
                        message.role === "user"
                          ? "bg-primary text-primary-foreground"
                          : message.kind === "error"
                            ? "bg-red-500 text-white"
                            : message.kind === "command"
                              ? "bg-purple-500 text-white"
                              : "bg-muted-foreground text-background"
                      }`}
                      aria-hidden="true"
                    >
                      {message.role === "user" ? (
                        <User className="w-4 h-4" />
                      ) : message.kind === "error" ? (
                        <AlertTriangle className="w-4 h-4" />
                      ) : message.kind === "command" ? (
                        <Terminal className="w-4 h-4" />
                      ) : (
                        <Brain className="w-4 h-4" />
                      )}
                    </div>
                  </div>
                  <div className={`flex-1 max-w-[85%] ${message.role === "user" ? "text-right" : "text-left"}`}>
                    <span className="sr-only">{message.role === "user" ? "You said:" : "Assistant:"}</span>
                    <div className={`inline-block p-3 rounded-lg text-left text-sm ${bubbleClass(message)}`}>
                      {message.role === "user" ? (
                        <p className="whitespace-pre-wrap break-words">{message.content}</p>
                      ) : (
                        <SimpleMarkdown text={message.content} />
                      )}
                    </div>
                    {/* Time differs between server and browser (clock + locale), so skip the hydration check */}
                    <div className="text-xs text-muted-foreground mt-1" suppressHydrationWarning>
                      {message.timestamp.toLocaleTimeString()}
                      {message.model ? ` · ${message.model}` : ""}
                    </div>
                  </div>
                </div>
              ))}

              {isBusy && (
                <div className="flex gap-3" role="status">
                  <div className="w-8 h-8 rounded-full bg-purple-500 flex items-center justify-center" aria-hidden="true">
                    <Brain className="w-4 h-4 text-white" />
                  </div>
                  <div className="inline-block p-3 rounded-lg bg-purple-50 dark:bg-purple-950/20">
                    <span className="flex items-center gap-2 text-sm text-purple-700 dark:text-purple-300">
                      <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                      Working on it…
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          <form onSubmit={handleSubmit} className="flex gap-2">
            <Input
              ref={inputRef}
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about a scam, or type /help"
              aria-label="Message the assistant"
              maxLength={4000}
              disabled={isBusy}
              className="font-mono bg-input-background backdrop-blur-sm"
            />
            <Button
              type="submit"
              disabled={!inputMessage.trim() || isBusy}
              size="icon"
              className="security-button"
              aria-label="Send message"
            >
              <Send className="w-4 h-4" aria-hidden="true" />
            </Button>
          </form>

          <Separator />

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
              <span className="text-sm font-medium">Quick commands</span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {QUICK_COMMANDS.map((cmd) => (
                <Button
                  key={cmd}
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setInputMessage(cmd);
                    inputRef.current?.focus();
                  }}
                  className="text-xs font-mono justify-start security-button"
                >
                  {cmd.trim()}
                </Button>
              ))}
            </div>
          </div>

          <Separator />

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
              <span className="text-sm font-medium">Try asking</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {SUGGESTED_QUESTIONS.map((question) => (
                <Button
                  key={question}
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => send(question)}
                  disabled={isBusy}
                  className="text-xs justify-start h-auto py-2 px-3 whitespace-normal text-left"
                >
                  <MessageSquare className="w-3 h-3 mr-2 flex-shrink-0" aria-hidden="true" />
                  {question}
                </Button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
