import { NextRequest, NextResponse } from 'next/server';
import { ChatOpenAI } from '@langchain/openai';
import { AIMessage, HumanMessage, SystemMessage } from '@langchain/core/messages';

/**
 * AI Chat API - Using Groq (100% FREE!)
 * Groq provides free AI inference with Llama 3.1 models
 * Get your free API key at: https://console.groq.com
 */

const SYSTEM_PROMPT = `You are PhishGuard AI, an advanced cybersecurity assistant specializing in:
- Phishing detection and prevention
- Threat intelligence analysis
- Security incident response
- Best practice recommendations
- Real-time threat assessments

You provide clear, actionable security advice with technical accuracy. Always prioritize user safety.
Format responses with markdown for better readability. Keep responses concise but informative.`;

export async function POST(request: NextRequest) {
  try {
    const { message, context } = await request.json();

    if (!message) {
      return NextResponse.json(
        { success: false, error: 'Message is required' },
        { status: 400 }
      );
    }

    // Check if Groq API key is configured
    if (!process.env.GROQ_API_KEY || process.env.GROQ_API_KEY.includes('your-key-here')) {
      // Use local fallback
      return NextResponse.json({
        success: true,
        response: getLocalAIResponse(message),
        model: 'PhishGuard-Local-AI-v2.1',
        fallback: true,
      });
    }

    try {
      // Sanitize context: only allow 'user' and 'assistant' roles to prevent prompt injection
      const validRoles = new Set(['user', 'assistant']);
      const sanitizedContext = (Array.isArray(context) ? context : [])
        .filter((msg: any) => validRoles.has(msg.role) && typeof msg.content === 'string')
        .map((msg: any) => msg.role === 'assistant'
          ? new AIMessage(msg.content)
          : new HumanMessage(msg.content));

      const model = new ChatOpenAI({
        apiKey: process.env.GROQ_API_KEY,
        model: 'llama-3.3-70b-versatile',
        temperature: 0.7,
        maxTokens: 1024,
        configuration: {
          baseURL: 'https://api.groq.com/openai/v1',
        },
      } as any);

      const completion = await model.invoke([
        new SystemMessage(SYSTEM_PROMPT),
        ...sanitizedContext,
        new HumanMessage(message),
      ]);

      const responseContent = normalizeMessageContent(completion.content) || 'No response generated';

      return NextResponse.json({
        success: true,
        response: responseContent,
        model: 'llama-3.3-70b-versatile',
        usage: completion.response_metadata,
        fallback: false,
      });
    } catch (error) {
      console.error('Groq API error:', error);

      // Fallback to local AI
      return NextResponse.json({
        success: true,
        response: getLocalAIResponse(message),
        model: 'PhishGuard-Local-AI-v2.1',
        fallback: true,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  } catch (error) {
    console.error('Chat API error:', error);

    return NextResponse.json({
      success: true,
      response: getLocalAIResponse(''),
      fallback: true,
      error: error instanceof Error ? error.message : 'Unknown error',
    }, { status: 200 });
  }
}

function normalizeMessageContent(content: unknown): string {
  if (typeof content === 'string') {
    return content;
  }

  if (Array.isArray(content)) {
    return content
      .map((part: any) => {
        if (typeof part === 'string') return part;
        if (part && typeof part.text === 'string') return part.text;
        if (part && typeof part.content === 'string') return part.content;
        return '';
      })
      .join('')
      .trim();
  }

  return '';
}

/**
 * Local AI fallback when Groq API is not available
 */
function getLocalAIResponse(message: string): string {
  const lowerMessage = message.toLowerCase();

  if (lowerMessage.includes('phishing') || lowerMessage.includes('phish')) {
    return `🎣 **Understanding Phishing Attacks**

Phishing is a cybersecurity attack where attackers impersonate legitimate entities to steal sensitive information.

**Common Signs:**
• 🚨 Urgency or threats ("Act now!")
• 📧 Suspicious sender addresses
• 🔗 Fake URLs (similar but not exact)
• 📝 Poor grammar and spelling
• 💰 Requests for sensitive info

**Protection:**
✅ Verify sender through official channels
✅ Check URLs before clicking
✅ Enable two-factor authentication
✅ Use PhishGuard to scan URLs

**Note:** For detailed AI responses, add your free Groq API key to .env.local`;
  }

  if (lowerMessage.includes('password')) {
    return `🔐 **Password Security**

**Best Practices:**
✅ 12+ characters minimum
✅ Mix uppercase, lowercase, numbers, symbols
✅ Unique password per account
✅ Use a password manager

**Two-Factor Authentication:**
🥇 Hardware keys (YubiKey)
🥈 Authenticator apps
🥉 SMS codes

**Note:** For detailed AI responses, add your free Groq API key to .env.local`;
  }

  return `👋 **PhishGuard AI Assistant**

I can help with:
• Phishing detection
• URL safety
• Email security
• Malware protection
• Password best practices

**Get Better Responses:**
Add your FREE Groq API key to unlock full AI capabilities!

1. Get free key at: https://console.groq.com
2. Add to .env.local:
   \`GROQ_API_KEY=your_key_here\`
3. Restart server

**Currently using local responses.** Type /help for commands.`;
}
