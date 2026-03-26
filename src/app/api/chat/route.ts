import { NextRequest, NextResponse } from 'next/server';
import Groq from 'groq-sdk';

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
      // Use Groq AI (FREE!)
      const groq = new Groq({
        apiKey: process.env.GROQ_API_KEY,
      });

      // Sanitize context: only allow 'user' and 'assistant' roles to prevent prompt injection
      const validRoles = new Set(['user', 'assistant']);
      const sanitizedContext = (context || [])
        .filter((msg: any) => validRoles.has(msg.role) && typeof msg.content === 'string')
        .map((msg: any) => ({ role: msg.role as 'user' | 'assistant', content: msg.content }));

      const messages = [
        { role: 'system' as const, content: SYSTEM_PROMPT },
        ...sanitizedContext,
        { role: 'user' as const, content: message },
      ];

      const completion = await groq.chat.completions.create({
        model: 'llama-3.3-70b-versatile', // Latest Llama 3.3 - Free and powerful!
        messages,
        temperature: 0.7,
        max_tokens: 1024,
        top_p: 1,
      });

      const responseContent = completion.choices[0]?.message?.content || 'No response generated';

      return NextResponse.json({
        success: true,
        response: responseContent,
        model: completion.model,
        usage: completion.usage,
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
