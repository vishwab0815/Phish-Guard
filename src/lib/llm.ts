/**
 * Groq model used by the AI assistant, message analysis and email analysis.
 * Groq retires models periodically (llama-3.3-70b-versatile was removed), so it
 * lives in one place and can be overridden with GROQ_MODEL without a code change.
 */
export const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b'
