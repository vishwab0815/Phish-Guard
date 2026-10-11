/** @jest-environment node */
/**
 * EmailAnalyzer unit tests (offline: URLAnalyzer, groq-sdk and the DB are mocked)
 */

const mockGroqCreate = jest.fn()

jest.mock('groq-sdk', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => ({
    chat: { completions: { create: (...args: unknown[]) => mockGroqCreate(...args) } },
  })),
}))

jest.mock('@/db', () => ({ db: {} }))

jest.mock('@/services/detection/urlAnalyzer', () => ({
  URLAnalyzer: {
    analyze: jest.fn(async (url: string) => {
      let host = ''
      try {
        host = new URL(url).hostname
      } catch {
        return { isValid: false, riskScore: 100, indicators: ['Invalid URL format'] }
      }
      if (/sbi-kyc|paypa1|evil/.test(host)) {
        return { isValid: true, riskScore: 80, indicators: ['Potential SBI impersonation - Domain mismatch detected'] }
      }
      return { isValid: true, riskScore: 0, indicators: [] }
    }),
  },
}))

import { EmailAnalyzer } from '@/services/email/emailAnalyzer'

const baseEmail = {
  from: 'Friend <friend@example.org>',
  to: 'me@example.com',
  subject: 'Hello',
  body: 'Hi there',
  headers: {} as Record<string, string>,
}

describe('EmailAnalyzer.parseRawEmail', () => {
  it('unfolds folded headers and lowercases header names', () => {
    const raw = [
      'Received: from mail.example.com',
      '  by mx.google.com with ESMTPS',
      'FROM: "Alice" <alice@example.com>',
      'subject: Hello',
      '\tworld',
      'Reply-To: other@example.net',
      'Return-Path: <bounce@example.com>',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'Body line one',
      'Body line two',
    ].join('\r\n')

    const parsed = EmailAnalyzer.parseRawEmail(raw)
    expect(parsed.headers['received']).toContain('by mx.google.com')
    expect(parsed.from).toBe('"Alice" <alice@example.com>')
    expect(parsed.subject).toBe('Hello world')
    expect(parsed.replyTo).toBe('other@example.net')
    expect(parsed.returnPath).toBe('<bounce@example.com>')
    expect(parsed.body).toBe('Body line one\nBody line two')
    expect(parsed.headers['FROM' as string]).toBeUndefined()
  })

  it('joins repeated headers in order', () => {
    const parsed = EmailAnalyzer.parseRawEmail(
      'Received: hop1\nReceived: hop2\nFrom: a@b.com\nSubject: x\n\nbody'
    )
    expect(parsed.headers['received']).toBe('hop1\nhop2')
  })

  it('prefers text/plain in multipart and decodes QP / base64 / encoded-words', () => {
    const html = Buffer.from('<p>Hello <a href="https://example.com">site</a></p>').toString('base64')
    const raw = [
      'From: =?UTF-8?B?U0JJIEJhbms=?= <x@example.com>',
      'Subject: =?utf-8?Q?Caf=C3=A9_news?=',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="outer"',
      '',
      '--outer',
      'Content-Type: multipart/alternative; boundary="inner"',
      '',
      '--inner',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      'Caf=C3=A9 is open. This line is soft=',
      ' wrapped.',
      '--inner',
      'Content-Type: text/html',
      'Content-Transfer-Encoding: base64',
      '',
      html,
      '--inner--',
      '--outer',
      'Content-Type: application/vnd.android.package-archive; name="update.apk"',
      'Content-Disposition: attachment; filename="update.apk"',
      'Content-Transfer-Encoding: base64',
      '',
      'AAAAAAAA',
      '--outer--',
    ].join('\n')

    const parsed = EmailAnalyzer.parseRawEmail(raw)
    expect(parsed.from).toBe('SBI Bank <x@example.com>')
    expect(parsed.subject).toBe('Café news')
    expect(parsed.body).toBe('Café is open. This line is soft wrapped.')
    expect(parsed.bodyHtml).toContain('<a href="https://example.com">')
    expect(parsed.attachments).toEqual([
      { filename: 'update.apk', contentType: 'application/vnd.android.package-archive', size: 6 },
    ])
  })

  it('treats text without headers as the body', () => {
    const text = 'Dear customer,\nYour account will be blocked today.\nRegards'
    const parsed = EmailAnalyzer.parseRawEmail(text)
    expect(parsed.from).toBe('')
    expect(parsed.subject).toBe('')
    expect(parsed.headers).toEqual({})
    expect(parsed.body).toBe(text)
  })

  it('does not mistake a "Note: ..." first line for a header block', () => {
    const parsed = EmailAnalyzer.parseRawEmail('Note: please read\nThis is the message')
    expect(parsed.headers).toEqual({})
    expect(parsed.body).toContain('Note: please read')
  })
})

describe('EmailAnalyzer.analyzeEmail', () => {
  const savedKey = process.env.GROQ_API_KEY

  beforeEach(() => {
    delete process.env.GROQ_API_KEY
    mockGroqCreate.mockReset()
  })

  afterAll(() => {
    if (savedKey) process.env.GROQ_API_KEY = savedKey
  })

  it('tolerates empty from/subject', async () => {
    const result = await EmailAnalyzer.analyzeEmail({ from: '', subject: '', body: 'hello', headers: {} })
    expect(result.threatLevel).toBe('SAFE')
    expect(result.senderReputation.domain).toBe('')
  })

  it('does not call a Return-Path with a trailing ">" spoofed', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      from: 'SBI <alerts@sbi.co.in>',
      headers: { 'Return-Path': '<bounce@alerts.sbi.co.in>' },
    })
    expect(result.isSpoofed).toBe(false)
    expect(result.headerAnalysis.returnPathDomain).toBe('alerts.sbi.co.in')
    expect(result.indicators.join(' ')).not.toMatch(/spoof|Return-Path/i)
  })

  it('treats an ESP Return-Path as a weak signal only', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      from: 'Acme News <news@acme.com>',
      headers: { 'return-path': '<bounces+123@em.sendgrid.net>' },
    })
    expect(result.isSpoofed).toBe(false)
    expect(result.riskScore).toBeLessThan(20)
  })

  it('detects SPF softfail from Authentication-Results and Received-SPF', async () => {
    const viaAuth = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      headers: { 'Authentication-Results': 'mx.google.com; spf=softfail smtp.mailfrom=x.com; dkim=none; dmarc=fail (p=NONE)' },
    })
    expect(viaAuth.headerAnalysis.spfResult).toBe('softfail')
    expect(viaAuth.headerAnalysis.dkimResult).toBe('none')
    expect(viaAuth.headerAnalysis.dmarcResult).toBe('fail')
    expect(viaAuth.headerAnalysis.authenticationSource).toBe('provided-headers')
    expect(viaAuth.indicators.some(i => /not independently verified/.test(i))).toBe(true)

    const viaReceived = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      headers: { 'RECEIVED-SPF': 'SoftFail (google.com: domain of transitioning x@y.com does not designate 1.2.3.4)' },
    })
    expect(viaReceived.headerAnalysis.spfResult).toBe('softfail')
  })

  it('reports authentication as not available when no auth headers exist', async () => {
    const result = await EmailAnalyzer.analyzeEmail(baseEmail)
    expect(result.headerAnalysis.authenticationSource).toBe('not-available')
    expect(result.notes.join(' ')).toMatch(/not available/)
    expect(result.riskScore).toBe(0)
  })

  it('flags Reply-To pointing away from a bank sender', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      from: 'HDFC Bank <alerts@hdfcbank.com>',
      replyTo: 'support@hdfc-helpdesk.co',
    })
    expect(result.headerAnalysis.replyToDomain).toBe('hdfc-helpdesk.co')
    expect(result.indicators.some(i => /Replies go to support@hdfc-helpdesk\.co/.test(i))).toBe(true)
  })

  it('flags "SBI Bank" display name sent from gmail.com', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      from: '"SBI Bank" <sbi.helpdesk2024@gmail.com>',
      subject: 'Account notice',
      body: 'Please contact us.',
    })
    expect(result.isSpoofed).toBe(true)
    expect(result.senderReputation.isFreeMail).toBe(true)
    expect(result.senderReputation.claimedBrand).toBe('SBI')
    expect(result.indicators.some(i => /free personal gmail\.com account/.test(i))).toBe(true)
    expect(result.riskScore).toBeGreaterThanOrEqual(40)
  })

  it('flags a display name that contains a different email address', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      from: '"service@paypal.com" <random@mailer.example.ru>',
    })
    expect(result.isSpoofed).toBe(true)
    expect(result.indicators.some(i => /shows the address service@paypal\.com/.test(i))).toBe(true)
  })

  it('flags lookalike sender domains', async () => {
    const result = await EmailAnalyzer.analyzeEmail({ ...baseEmail, from: 'SBI Alerts <alerts@sbi-kyc-update.com>' })
    expect(result.senderReputation.isLookalikeDomain).toBe(true)
    expect(result.isSpoofed).toBe(true)
  })

  it('flags OTP requests as HIGH but not CRITICAL on content alone', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      subject: 'Verification pending',
      body: 'Dear customer, please share the OTP you received on your mobile to complete the verification.',
    })
    expect(result.contentAnalysis.requestsCredentials).toBe(true)
    expect(result.threatLevel).toBe('HIGH')
    expect(result.recommendations.join(' ')).toMatch(/Never share an OTP/)
    expect(result.recommendations.join(' ')).toMatch(/1930/)
  })

  it('does not treat "never share your OTP" warnings as requests', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      body: 'Your OTP for login is 482910. Never share your OTP with anyone. Do not share this code.',
    })
    expect(result.contentAnalysis.requestsCredentials).toBe(false)
    expect(result.riskScore).toBeLessThan(20)
  })

  it('keeps keyword-only emails below CRITICAL', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      subject: 'URGENT: KYC update pending - account will be blocked',
      body:
        'Your KYC is expired. Your account will be blocked today. Link your PAN card immediately. ' +
        'Electricity will be disconnected tonight. Claim your refund now. You have won KBC lottery.',
    })
    expect(result.contentAnalysis.scamCategories).toEqual(
      expect.arrayContaining(['kyc', 'pan_aadhaar', 'account_block', 'electricity', 'refund', 'lottery'])
    )
    expect(result.threatLevel).not.toBe('CRITICAL')
    expect(result.riskScore).toBeLessThanOrEqual(75)
  })

  it('reaches CRITICAL when impersonation, links and OTP request combine', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      from: '"SBI Bank" <sbi.kyc.team@gmail.com>',
      subject: 'KYC update pending - account will be blocked',
      body: 'Update KYC at https://sbi-kyc-update.com/login and share the OTP with our executive.',
    })
    expect(result.threatLevel).toBe('CRITICAL')
    expect(result.isPhishing).toBe(true)
  })

  it('flags href/visible-text mismatches and analyzes links with URLAnalyzer', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      body: '',
      bodyHtml: '<p>Login: <a href="http://evil.example.ru/hdfc/login">https://www.hdfcbank.com</a></p>',
    })
    const link = result.contentAnalysis.links.find(l => l.host === 'evil.example.ru')
    expect(link?.textMismatch).toBe(true)
    expect(result.indicators.some(i => /Link text says "https:\/\/www\.hdfcbank\.com" but actually opens evil\.example\.ru/.test(i))).toBe(true)
    expect(result.contentAnalysis.hasSuspiciousLinks).toBeGreaterThan(0)
  })

  it('no longer flags www.gamespot.com as a ".ga" high-risk TLD', async () => {
    const result = await EmailAnalyzer.analyzeEmail({ ...baseEmail, body: 'Read https://www.gamespot.com/reviews today' })
    expect(result.contentAnalysis.hasSuspiciousLinks).toBe(0)
    expect(result.contentAnalysis.links).toHaveLength(1)
  })

  it('keeps a benign newsletter SAFE/LOW', async () => {
    const raw = [
      'Received: from o1.em.sendgrid.net by mx.google.com',
      'Return-Path: <bounces+42@em.sendgrid.net>',
      'Authentication-Results: mx.google.com; dkim=pass header.i=@acme.com; spf=pass smtp.mailfrom=em.sendgrid.net; dmarc=pass header.from=acme.com',
      'From: Acme Weekly <news@acme.com>',
      'To: reader@example.com',
      'Subject: This week at Acme: 5 stories you might like',
      'Message-ID: <abc123@acme.com>',
      'Date: Mon, 5 Oct 2026 10:00:00 +0000',
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      "Hi reader, here are this week's top stories from our blog.",
      'Read more: https://acme.com/blog/weekly-42',
      'You are receiving this because you subscribed. Unsubscribe: https://acme.com/unsubscribe',
    ].join('\n')
    const parsed = EmailAnalyzer.parseRawEmail(raw)
    const result = await EmailAnalyzer.analyzeEmail(parsed)
    expect(['SAFE', 'LOW']).toContain(result.threatLevel)
    expect(result.isSpoofed).toBe(false)
    expect(result.headerAnalysis.dmarcResult).toBe('pass')
    expect(result.senderReputation.reputationChecked).toBe(false)
  })

  it('flags APK and disguised attachments', async () => {
    const result = await EmailAnalyzer.analyzeEmail({
      ...baseEmail,
      attachments: [
        { filename: 'SBI_KYC.apk', contentType: 'application/vnd.android.package-archive', size: 1000 },
        { filename: 'invoice.pdf.exe', contentType: 'application/octet-stream', size: 1000 },
      ],
    })
    expect(result.contentAnalysis.hasSuspiciousAttachments).toBe(2)
    expect(result.recommendations.join(' ')).toMatch(/Play Store/)
    expect(['MEDIUM', 'HIGH', 'CRITICAL']).toContain(result.threatLevel)
  })

  it('clamps and validates AI output and treats it as one signal', async () => {
    process.env.GROQ_API_KEY = 'test-key'
    mockGroqCreate.mockResolvedValue({
      choices: [{ message: { content: JSON.stringify({ riskScore: 500, threatLevel: 'BANANA', indicators: ['x', 42] }) } }],
    })
    const result = await EmailAnalyzer.analyzeEmail(baseEmail)
    expect(result.aiAnalysis.used).toBe(true)
    expect(result.aiAnalysis.riskScore).toBe(100)
    expect(result.aiAnalysis.threatLevel).toBe('CRITICAL')
    // AI alone cannot push a clean email past LOW
    expect(['SAFE', 'LOW']).toContain(result.threatLevel)

    const [params, options] = mockGroqCreate.mock.calls[0]
    expect(options.signal).toBeDefined()
    expect(params.messages[0].content).toMatch(/UNTRUSTED DATA/)
  })

  it('continues without AI when the call fails', async () => {
    process.env.GROQ_API_KEY = 'test-key'
    mockGroqCreate.mockRejectedValue(new Error('network down'))
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {})
    const result = await EmailAnalyzer.analyzeEmail(baseEmail)
    spy.mockRestore()
    expect(result.aiAnalysis.used).toBe(false)
    expect(result.aiAnalysis.error).toMatch(/network down/)
    expect(result.threatLevel).toBe('SAFE')
  })

  it('truncates the body sent to the AI', async () => {
    process.env.GROQ_API_KEY = 'test-key'
    mockGroqCreate.mockResolvedValue({ choices: [{ message: { content: '{"riskScore": 10}' } }] })
    await EmailAnalyzer.analyzeEmail({ ...baseEmail, body: 'a'.repeat(20000) })
    const [params] = mockGroqCreate.mock.calls[0]
    expect(params.messages[1].content.length).toBeLessThan(7000)
  })
})
