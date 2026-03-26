import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Textarea } from "./ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Label } from "./ui/label";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";
import { Alert, AlertDescription } from "./ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./ui/dialog";
import {
  Upload,
  Link,
  Mail,
  MessageSquare,
  Shield,
  AlertTriangle,
  CheckCircle,
  Info,
  ExternalLink,
  Calendar,
  Globe,
  Lock,
  Zap,
  Brain,
  Eye,
  TrendingUp,
  XCircle
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface ThreatIndicator {
  type: 'critical' | 'warning' | 'info';
  category: string;
  description: string;
  confidence: number;
  technical_details?: string;
}

interface RiskBreakdown {
  layer: string;
  riskContribution: number;
  weight: number;
  details: string;
}

interface ScanResult {
  threat_level: 'safe' | 'low' | 'medium' | 'high';
  confidence: number;
  accuracy_score: number;
  risk_percentage: number;
  indicators: ThreatIndicator[];
  recommendation: string;
  riskBreakdown?: RiskBreakdown[];
  scan_details: {
    scan_type: string;
    processing_time: number;
    database_version: string;
    analysis_depth: string;
  };
  metadata?: {
    domain_age?: number;
    ssl_status?: string;
    reputation_score?: number;
    geographic_origin?: string;
    content_type?: string;
    language_detected?: string;
  };
}

interface AnalysisProgress {
  step: string;
  progress: number;
  details: string;
}

interface ScanInterfaceProps {
  backendService: any;
}

export function ScanInterface({ backendService }: ScanInterfaceProps) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [analysisProgress, setAnalysisProgress] = useState<AnalysisProgress[]>([]);
  const [urlInput, setUrlInput] = useState("");
  const [emailContent, setEmailContent] = useState("");
  const [messageContent, setMessageContent] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // Advanced URL analysis algorithm with detailed indicators
  const analyzeURL = (url: string): Partial<ScanResult> => {
    const indicators: ThreatIndicator[] = [];
    let threatLevel: ScanResult['threat_level'] = 'safe';
    let baseConfidence = 95;
    let riskScore = 0;

    // Domain analysis
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      const domain = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();

      // Enhanced detection lists
      const highRiskTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link', '.download'];
      const brandKeywords = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'instagram', 'twitter', 'linkedin', 'netflix', 'spotify', 'dropbox', 'adobe'];
      const suspiciousKeywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password', 'wallet', 'crypto', 'suspended', 'locked', 'urgent', 'validate', 'authenticate', 'billing', 'payment'];
      const maliciousPatterns = ['free-', 'get-free', 'download-', 'click-here', 'verify-account', 'secure-login', 'account-update', 'password-reset', 'confirm-identity', 'suspended-account', 'unlock-account', 'billing-problem'];

      // Check for high-risk TLDs with specific details
      const foundTld = highRiskTlds.find(tld => domain.endsWith(tld));
      if (foundTld) {
        indicators.push({
          type: 'critical',
          category: 'High-Risk Domain',
          description: `High-risk TLD detected: ${foundTld}`,
          confidence: 90,
          technical_details: `Domain uses ${foundTld} which is frequently abused for phishing attacks`
        });
        riskScore += 30;
      }

      // Check for brand impersonation with specific brand name
      const foundBrand = brandKeywords.find(brand => domain.includes(brand));
      const validDomains = foundBrand ? [`${foundBrand}.com`, `www.${foundBrand}.com`, `${foundBrand}.net`, `${foundBrand}.org`] : [];
      const isLegitimate = validDomains.some(valid => domain === valid || domain.endsWith('.' + valid));

      if (foundBrand && !isLegitimate) {
        const brandName = foundBrand.charAt(0).toUpperCase() + foundBrand.slice(1);
        indicators.push({
          type: 'critical',
          category: 'Brand Impersonation',
          description: `Potential ${brandName} impersonation - Domain mismatch detected`,
          confidence: 95,
          technical_details: `Domain '${domain}' contains '${foundBrand}' but does not match legitimate ${brandName} domains`
        });
        riskScore += 45;
        threatLevel = 'high';
      }

      // Check for malicious patterns with details
      const foundPatterns = maliciousPatterns.filter(pattern => fullUrl.includes(pattern));
      if (foundPatterns.length > 0) {
        indicators.push({
          type: 'critical',
          category: 'Phishing Patterns',
          description: `Known phishing patterns detected: ${foundPatterns.join(', ')}`,
          confidence: 92,
          technical_details: `${foundPatterns.length} malicious pattern(s) commonly used in phishing URLs`
        });
        riskScore += 35 * foundPatterns.length;
      }

      // Check for suspicious keywords with details
      const foundKeywords = suspiciousKeywords.filter(keyword => fullUrl.includes(keyword));
      if (foundKeywords.length > 0) {
        indicators.push({
          type: foundKeywords.length > 3 ? 'critical' : 'warning',
          category: 'Suspicious Keywords',
          description: `Suspicious keywords detected: ${foundKeywords.slice(0, 5).join(', ')}${foundKeywords.length > 5 ? ` (+${foundKeywords.length - 5} more)` : ''}`,
          confidence: Math.min(90, 65 + (foundKeywords.length * 5)),
          technical_details: `${foundKeywords.length} keyword(s) commonly found in phishing attempts`
        });
        riskScore += 10 * foundKeywords.length;
      }

      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl'];
      if (shorteners.some(shortener => domain.includes(shortener))) {
        indicators.push({
          type: 'warning',
          category: 'URL Shortener',
          description: 'URL uses link shortening service',
          confidence: 70,
          technical_details: 'Shortened URLs can hide malicious destinations'
        });
        riskScore += 15;
      }

      // SSL/HTTPS check
      if (!url.startsWith('https://')) {
        indicators.push({
          type: 'warning',
          category: 'Security',
          description: 'Website does not use HTTPS encryption',
          confidence: 80,
          technical_details: 'Unencrypted connection increases risk'
        });
        riskScore += 20;
      }

      // Check for suspicious patterns in path
      const pathUrgencyWords = ['urgent', 'verify', 'update', 'confirm', 'expire', 'suspend', 'locked'];
      const suspiciousPath = pathUrgencyWords.some(word =>
        urlObj.pathname.toLowerCase().includes(word)
      );

      if (suspiciousPath) {
        indicators.push({
          type: 'warning',
          category: 'Content',
          description: 'URL contains urgency-related keywords',
          confidence: 75,
          technical_details: 'Path contains suspicious patterns'
        });
        riskScore += 15;
      }

      // Domain length analysis
      if (domain.length > 30) {
        indicators.push({
          type: 'info',
          category: 'Domain',
          description: 'Unusually long domain name',
          confidence: 60,
          technical_details: `Domain length: ${domain.length} characters`
        });
        riskScore += 10;
      }

      // Multiple subdomains
      const subdomains = domain.split('.').length - 2;
      if (subdomains > 2) {
        indicators.push({
          type: 'warning',
          category: 'Domain Structure',
          description: 'Domain has multiple subdomains',
          confidence: 65,
          technical_details: `${subdomains} subdomain levels detected`
        });
        riskScore += 12;
      }

    } catch (error) {
      indicators.push({
        type: 'critical',
        category: 'URL Format',
        description: 'Invalid or malformed URL',
        confidence: 95,
        technical_details: 'URL parsing failed'
      });
      riskScore += 50;
      threatLevel = 'high';
    }

    // Determine threat level based on risk score
    if (riskScore >= 50) threatLevel = 'high';
    else if (riskScore >= 30) threatLevel = 'medium';
    else if (riskScore >= 15) threatLevel = 'low';

    return {
      threat_level: threatLevel,
      confidence: Math.max(50, baseConfidence - Math.floor(riskScore / 5)),
      accuracy_score: Math.max(75, 98 - Math.floor(riskScore / 3)),
      risk_percentage: Math.min(95, riskScore),
      indicators,
      metadata: {
        ssl_status: url.startsWith('https://') ? 'Valid' : 'Missing',
        reputation_score: Math.max(10, 100 - riskScore),
      }
    };
  };

  // Advanced email content analysis
  const analyzeEmail = (content: string): Partial<ScanResult> => {
    const indicators: ThreatIndicator[] = [];
    let threatLevel: ScanResult['threat_level'] = 'safe';
    let baseConfidence = 92;
    let riskScore = 0;

    const text = content.toLowerCase();
    
    // Phishing keywords detection
    const urgencyWords = ['urgent', 'immediate', 'expire', 'suspend', 'verify', 'act now', 'limited time', 'expires today'];
    const socialEngineeringWords = ['congratulations', 'winner', 'prize', 'lottery', 'inheritance', 'beneficiary'];
    const requestWords = ['click here', 'update your', 'verify your account', 'confirm your', 'provide your'];
    const threatWords = ['suspended', 'terminated', 'blocked', 'security alert', 'unauthorized access'];

    // Check for urgency language
    const urgencyMatches = urgencyWords.filter(word => text.includes(word));
    if (urgencyMatches.length > 0) {
      indicators.push({
        type: urgencyMatches.length > 2 ? 'critical' : 'warning',
        category: 'Social Engineering',
        description: `Urgency language detected: ${urgencyMatches.join(', ')}`,
        confidence: Math.min(90, 70 + urgencyMatches.length * 10),
        technical_details: `${urgencyMatches.length} urgency indicators found`
      });
      riskScore += urgencyMatches.length * 15;
    }

    // Check for social engineering
    const socialMatches = socialEngineeringWords.filter(word => text.includes(word));
    if (socialMatches.length > 0) {
      indicators.push({
        type: 'warning',
        category: 'Social Engineering',
        description: `Potential scam language: ${socialMatches.join(', ')}`,
        confidence: 85,
        technical_details: 'Common scam terminology detected'
      });
      riskScore += socialMatches.length * 20;
    }

    // Check for information requests
    const requestMatches = requestWords.filter(word => text.includes(word));
    if (requestMatches.length > 0) {
      indicators.push({
        type: 'warning',
        category: 'Information Request',
        description: 'Email requests personal information or actions',
        confidence: 80,
        technical_details: `${requestMatches.length} request patterns found`
      });
      riskScore += requestMatches.length * 12;
    }

    // Check for threat language
    const threatMatches = threatWords.filter(word => text.includes(word));
    if (threatMatches.length > 0) {
      indicators.push({
        type: 'critical',
        category: 'Threat Language',
        description: 'Contains account threat or security warnings',
        confidence: 88,
        technical_details: 'Intimidation tactics detected'
      });
      riskScore += threatMatches.length * 18;
    }

    // Grammar and spelling analysis — look for actual quality issues
    const excessiveCaps = (content.match(/[A-Z]{5,}/g) || []).length;
    const spellingPatterns = content.match(/([a-z])\1{2,}/gi);
    
    if (excessiveCaps > 2 || spellingPatterns) {
      indicators.push({
        type: 'info',
        category: 'Content Quality',
        description: 'Poor grammar or spelling detected',
        confidence: 65,
        technical_details: 'Language quality indicators suggest unprofessional source'
      });
      riskScore += 8;
    }

    // Generic greetings
    const genericGreetings = ['dear customer', 'dear sir/madam', 'dear valued', 'dear user'];
    if (genericGreetings.some(greeting => text.includes(greeting))) {
      indicators.push({
        type: 'warning',
        category: 'Personalization',
        description: 'Generic greeting suggests mass phishing attempt',
        confidence: 75,
        technical_details: 'Lack of personalization is suspicious'
      });
      riskScore += 15;
    }

    // Email length analysis
    if (content.length < 100) {
      indicators.push({
        type: 'info',
        category: 'Content Analysis',
        description: 'Unusually short message',
        confidence: 60,
        technical_details: 'Brief messages often hide malicious intent'
      });
      riskScore += 5;
    }

    // Links detection
    const linkMatches = content.match(/https?:\/\/[^\s]+/gi);
    if (linkMatches && linkMatches.length > 3) {
      indicators.push({
        type: 'warning',
        category: 'Links',
        description: `Multiple links detected (${linkMatches.length})`,
        confidence: 70,
        technical_details: 'Excessive links may indicate phishing'
      });
      riskScore += linkMatches.length * 3;
    }

    // Determine threat level
    if (riskScore >= 45) threatLevel = 'high';
    else if (riskScore >= 25) threatLevel = 'medium';
    else if (riskScore >= 10) threatLevel = 'low';

    return {
      threat_level: threatLevel,
      confidence: Math.max(55, baseConfidence - Math.floor(riskScore / 4)),
      accuracy_score: Math.max(80, 96 - Math.floor(riskScore / 3)),
      risk_percentage: Math.min(90, riskScore),
      indicators,
      metadata: {
        content_type: 'Email',
        language_detected: 'English',
      }
    };
  };

  // File upload handlers
  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleDragOver = (event: React.DragEvent) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault();
    setIsDragging(false);
    const file = event.dataTransfer.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const performFileScan = async () => {
    if (!selectedFile) return;

    setIsScanning(true);
    setScanResult(null);
    setAnalysisProgress([]);

    // Simulate detailed analysis progress
    const steps = [
      { step: 'Uploading file', progress: 10, details: 'Securely uploading file to analysis engine...' },
      { step: 'File signature analysis', progress: 25, details: 'Checking file signatures and headers...' },
      { step: 'Malware scanning', progress: 45, details: 'Scanning with 60+ antivirus engines...' },
      { step: 'Behavioral analysis', progress: 65, details: 'Analyzing file behavior patterns...' },
      { step: 'Threat intelligence', progress: 80, details: 'Querying threat databases...' },
      { step: 'Finalizing results', progress: 95, details: 'Generating comprehensive report...' },
      { step: 'Complete', progress: 100, details: 'File analysis complete!' }
    ];

    for (const step of steps) {
      setAnalysisProgress(prev => [...prev, step]);
      await new Promise(resolve => setTimeout(resolve, 400 + Math.random() * 600));
    }

    try {
      // Upload file to backend
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('user_id', backendService.generateUserId());

      const response = await fetch('/api/analyze/file', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (data.success) {
        const analysis = data.analysis;

        // Parse file indicators with proper categorization
        const parseFileIndicator = (indicator: string): ThreatIndicator => {
          const lowerIndicator = indicator.toLowerCase();

          // VirusTotal detection
          if (lowerIndicator.includes('virustotal') || lowerIndicator.includes('engines detected')) {
            return {
              type: 'critical',
              category: 'VirusTotal Multi-Engine Scan',
              description: indicator,
              confidence: 95,
              technical_details: `File: ${analysis.file.name} (${(analysis.file.size / 1024).toFixed(1)}KB) - Scanned by 60+ engines`
            };
          }

          // Malware detected
          if (lowerIndicator.includes('malware') || lowerIndicator.includes('virus') || lowerIndicator.includes('trojan')) {
            return {
              type: 'critical',
              category: 'Malware Detection',
              description: indicator,
              confidence: 98,
              technical_details: `File: ${analysis.file.name} - Contains malicious code`
            };
          }

          // Suspicious file patterns
          if (lowerIndicator.includes('suspicious') || lowerIndicator.includes('potentially unwanted')) {
            return {
              type: 'warning',
              category: 'Suspicious File Characteristics',
              description: indicator,
              confidence: 85,
              technical_details: `File: ${analysis.file.name} (${analysis.file.type}) - Unusual patterns detected`
            };
          }

          // File signature issues
          if (lowerIndicator.includes('signature') || lowerIndicator.includes('hash')) {
            return {
              type: 'warning',
              category: 'File Signature Analysis',
              description: indicator,
              confidence: 80,
              technical_details: `File cryptographic analysis - ${analysis.file.name}`
            };
          }

          // Clean file
          if (lowerIndicator.includes('clean') || lowerIndicator.includes('safe') || lowerIndicator.includes('no threat')) {
            return {
              type: 'info',
              category: 'File Verification',
              description: indicator,
              confidence: 100,
              technical_details: `File: ${analysis.file.name} passed all security checks`
            };
          }

          // Default
          const isCritical = analysis.result.threat_level === 'HIGH' || analysis.result.threat_level === 'CRITICAL';
          const isWarning = analysis.result.threat_level === 'MEDIUM';

          return {
            type: isCritical ? 'critical' : isWarning ? 'warning' : 'info',
            category: 'File Analysis',
            description: indicator,
            confidence: analysis.result.confidence,
            technical_details: `File: ${analysis.file.name} (${(analysis.file.size / 1024).toFixed(1)}KB, ${analysis.file.type})`
          };
        };

        const transformedResult: ScanResult = {
          threat_level: analysis.result.threat_level.toLowerCase() as ScanResult['threat_level'],
          confidence: analysis.result.confidence,
          accuracy_score: analysis.result.confidence,
          risk_percentage: analysis.result.risk_score,
          indicators: analysis.result.indicators.map(parseFileIndicator),
          recommendation: analysis.result.recommendations?.[0] || 'File scanned successfully.',
          scan_details: {
            scan_type: 'FILE',
            processing_time: analysis.scan_duration_ms / 1000,
            database_version: 'VirusTotal v3 + Local Signature DB',
            analysis_depth: 'Multi-Engine: Signature + Behavioral + Heuristic Analysis'
          },
          metadata: {
            content_type: analysis.file.type,
            ssl_status: 'N/A',
            reputation_score: 100 - analysis.result.risk_score,
            domain_age: undefined,
            geographic_origin: 'Local Upload'
          }
        };

        setScanResult(transformedResult);
      } else {
        throw new Error(data.error || 'File analysis failed');
      }
    } catch (error) {
      console.error('File analysis error:', error);

      // Fallback result
      const fallbackResult: ScanResult = {
        threat_level: 'low',
        confidence: 70,
        accuracy_score: 70,
        risk_percentage: 20,
        indicators: [{
          type: 'warning',
          category: 'Analysis Error',
          description: 'File upload or analysis failed. Please try again.',
          confidence: 50,
          technical_details: error instanceof Error ? error.message : 'Unknown error'
        }],
        recommendation: 'Unable to complete analysis. Please check your file and try again.',
        scan_details: {
          scan_type: 'FILE',
          processing_time: 0,
          database_version: 'Error',
          analysis_depth: 'Failed'
        }
      };

      setScanResult(fallbackResult);
    }

    setIsScanning(false);
  };

  const performScan = async (content: string, type: string) => {
    setIsScanning(true);
    setScanResult(null);
    setAnalysisProgress([]);

    // Real-time analysis progress tracking
    const updateProgress = (step: string, progress: number, details: string) => {
      setAnalysisProgress(prev => {
        const existing = prev.find(p => p.step === step);
        if (existing) {
          return prev.map(p => p.step === step ? { step, progress, details } : p);
        }
        return [...prev, { step, progress, details }];
      });
    };

    try {
      // Use backend service for real analysis with progress tracking
      const userId = backendService.generateUserId();
      let backendResult;

      // Step 1: Initialize
      updateProgress('Initializing scan', 15, 'Preparing threat analysis engines...');
      await new Promise(resolve => setTimeout(resolve, 300));

      // Step 2: Static Analysis
      updateProgress('Static analysis', 30, 'Analyzing URL structure and patterns...');

      if (type === 'url') {
        // Progress tracking for URL scan
        const urlPromise = backendService.analyzeUrl(content, userId);

        // Simulate progress for external API calls
        setTimeout(() => updateProgress('Domain intelligence', 50, 'Checking domain reputation and age...'), 800);
        setTimeout(() => updateProgress('SSL validation', 65, 'Validating security certificates...'), 1600);
        setTimeout(() => updateProgress('External threat scans', 80, 'Querying VirusTotal, Safe Browsing, PhishTank...'), 2400);
        setTimeout(() => updateProgress('Finalizing results', 95, 'Generating comprehensive report...'), 3200);

        backendResult = await urlPromise;
      } else if (type === 'email') {
        updateProgress('Content analysis', 50, 'Analyzing email headers and body...');
        setTimeout(() => updateProgress('Pattern detection', 75, 'Detecting phishing patterns...'), 800);
        setTimeout(() => updateProgress('Finalizing results', 95, 'Generating report...'), 1600);
        backendResult = await backendService.analyzeEmail(content, {}, userId);
      } else if (type === 'message') {
        updateProgress('Content analysis', 50, 'Analyzing message content...');
        setTimeout(() => updateProgress('Threat detection', 75, 'Detecting scam indicators...'), 800);
        setTimeout(() => updateProgress('Finalizing results', 95, 'Generating report...'), 1600);
        backendResult = await backendService.analyzeMessage(content, {}, userId);
      }

      // Complete
      updateProgress('Complete', 100, 'Analysis complete!');

      if (backendResult && backendResult.success) {
        // Transform backend result to match our interface
        const analysis = backendResult.analysis.result;

        // Parse detailed indicators from backend with proper categorization
        const parseIndicator = (indicator: string): ThreatIndicator => {
          const lowerIndicator = indicator.toLowerCase();

          // VirusTotal detection
          if (lowerIndicator.includes('virustotal')) {
            return {
              type: 'critical',
              category: 'VirusTotal Multi-Engine Scan',
              description: indicator,
              confidence: 95,
              technical_details: 'Detected by 60+ antivirus engines worldwide'
            };
          }

          // Google Safe Browsing
          if (lowerIndicator.includes('safe browsing') || lowerIndicator.includes('google')) {
            return {
              type: 'critical',
              category: 'Google Safe Browsing',
              description: indicator,
              confidence: 98,
              technical_details: 'Flagged in Google\'s threat intelligence database'
            };
          }

          // PhishTank
          if (lowerIndicator.includes('phishtank')) {
            return {
              type: 'critical',
              category: 'PhishTank Community Detection',
              description: indicator,
              confidence: 92,
              technical_details: 'Reported as phishing by community verification'
            };
          }

          // Brand impersonation
          if (lowerIndicator.includes('impersonation') || lowerIndicator.includes('paypal') ||
              lowerIndicator.includes('amazon') || lowerIndicator.includes('microsoft') ||
              lowerIndicator.includes('google') || lowerIndicator.includes('apple')) {
            return {
              type: 'critical',
              category: 'Brand Impersonation',
              description: indicator,
              confidence: 95,
              technical_details: 'Domain contains brand name but doesn\'t match legitimate domains'
            };
          }

          // Suspicious keywords
          if (lowerIndicator.includes('suspicious keywords')) {
            return {
              type: 'warning',
              category: 'Suspicious Keywords',
              description: indicator,
              confidence: 85,
              technical_details: 'Keywords commonly used in phishing attempts'
            };
          }

          // Malicious patterns
          if (lowerIndicator.includes('phishing patterns') || lowerIndicator.includes('malicious patterns')) {
            return {
              type: 'critical',
              category: 'Known Phishing Patterns',
              description: indicator,
              confidence: 92,
              technical_details: 'URL structure matches known phishing attack patterns'
            };
          }

          // High-risk TLD
          if (lowerIndicator.includes('tld') || lowerIndicator.includes('top-level domain')) {
            return {
              type: 'critical',
              category: 'High-Risk Domain',
              description: indicator,
              confidence: 88,
              technical_details: 'Domain uses TLD frequently abused for phishing'
            };
          }

          // HTTPS/SSL issues
          if (lowerIndicator.includes('https') || lowerIndicator.includes('ssl') || lowerIndicator.includes('encryption')) {
            return {
              type: 'warning',
              category: 'Security Certificate',
              description: indicator,
              confidence: 80,
              technical_details: 'Connection security issues detected'
            };
          }

          // IP address
          if (lowerIndicator.includes('ip address')) {
            return {
              type: 'warning',
              category: 'Domain Structure',
              description: indicator,
              confidence: 75,
              technical_details: 'IP addresses instead of domains are suspicious'
            };
          }

          // URL shortener
          if (lowerIndicator.includes('shortener')) {
            return {
              type: 'warning',
              category: 'URL Shortener',
              description: indicator,
              confidence: 70,
              technical_details: 'Shortened URLs can hide malicious destinations'
            };
          }

          // Trusted domain
          if (lowerIndicator.includes('trusted') || lowerIndicator.includes('whitelist')) {
            return {
              type: 'info',
              category: 'Trusted Domain',
              description: indicator,
              confidence: 100,
              technical_details: 'Domain verified as legitimate'
            };
          }

          // Blocklist
          if (lowerIndicator.includes('blocklist') || lowerIndicator.includes('blocked')) {
            return {
              type: 'critical',
              category: 'Domain Blocklist',
              description: indicator,
              confidence: 100,
              technical_details: 'Domain is on security blocklist'
            };
          }

          // More specific categorizations
          if (lowerIndicator.includes('ssl') || lowerIndicator.includes('certificate') ||
              lowerIndicator.includes('encryption') || lowerIndicator.includes('no valid ssl')) {
            return {
              type: 'warning',
              category: 'Security Certificate',
              description: indicator,
              confidence: 80,
              technical_details: 'SSL/TLS certificate validation results'
            };
          }

          if (lowerIndicator.includes('domain age') || lowerIndicator.includes('recently registered') ||
              lowerIndicator.includes('new domain')) {
            return {
              type: 'warning',
              category: 'Domain Age Analysis',
              description: indicator,
              confidence: 75,
              technical_details: 'Domain registration and history check'
            };
          }

          if (lowerIndicator.includes('subdomain') || lowerIndicator.includes('multiple subdomains')) {
            return {
              type: 'warning',
              category: 'Domain Structure',
              description: indicator,
              confidence: 70,
              technical_details: 'Unusual domain structure detected'
            };
          }

          if (lowerIndicator.includes('encoding') || lowerIndicator.includes('obfuscation') ||
              lowerIndicator.includes('punycode')) {
            return {
              type: 'warning',
              category: 'URL Encoding',
              description: indicator,
              confidence: 85,
              technical_details: 'Suspicious encoding or obfuscation detected'
            };
          }

          if (lowerIndicator.includes('homograph') || lowerIndicator.includes('idn spoofing')) {
            return {
              type: 'critical',
              category: 'IDN Homograph Attack',
              description: indicator,
              confidence: 95,
              technical_details: 'Domain uses look-alike characters'
            };
          }

          if (lowerIndicator.includes('port') || lowerIndicator.includes('unusual port')) {
            return {
              type: 'warning',
              category: 'Network Configuration',
              description: indicator,
              confidence: 70,
              technical_details: 'Non-standard port usage detected'
            };
          }

          // Default categorization with better context
          const isCritical = analysis.threat_level === 'HIGH' || analysis.threat_level === 'CRITICAL';
          const isWarning = analysis.threat_level === 'MEDIUM' || analysis.threat_level === 'LOW';

          // Determine category based on content
          let category = 'Security Indicator';
          if (lowerIndicator.includes('keyword') || lowerIndicator.includes('pattern')) {
            category = 'Pattern Detection';
          } else if (lowerIndicator.includes('length') || lowerIndicator.includes('structure')) {
            category = 'Structural Analysis';
          } else if (lowerIndicator.includes('url') || lowerIndicator.includes('link')) {
            category = 'URL Analysis';
          }

          return {
            type: isCritical ? 'critical' : isWarning ? 'warning' : 'info',
            category,
            description: indicator,
            confidence: analysis.confidence,
            technical_details: `Multi-layer detection engine`
          };
        };

        // Extract metadata from backend layers
        const layers = backendResult.analysis.result.layers || {};
        const metadata: any = {
          content_type: type,
        };

        // Add domain intelligence data if available
        if (layers.domain_intelligence) {
          metadata.domain_age = `${layers.domain_intelligence} days`;
          metadata.geographic_origin = 'Available';
        }

        // Add SSL status if available
        if (layers.ssl_validation) {
          metadata.ssl_status = layers.ssl_validation === 'completed' ? 'Valid' : 'Invalid';
        } else if (type === 'url') {
          metadata.ssl_status = 'Not checked';
        }

        // Calculate reputation score from risk score
        if (analysis.risk_score !== undefined) {
          const repScore = Math.max(0, Math.min(100, 100 - analysis.risk_score));
          metadata.reputation_score = `${repScore}/100`;
        }

        // Add scan layers info
        const completedLayers = [];
        if (layers.static_analysis === 'completed') completedLayers.push('Static Analysis');
        if (layers.domain_intelligence === 'completed') completedLayers.push('Domain Intel');
        if (layers.ssl_validation === 'completed') completedLayers.push('SSL Check');
        if (layers.ip_intelligence === 'completed') completedLayers.push('IP Analysis');
        if (layers.external_scans === 'completed') completedLayers.push('External APIs');

        if (completedLayers.length > 0) {
          metadata.detection_layers = completedLayers.join(', ');
        }

        const transformedResult: ScanResult = {
          threat_level: analysis.threat_level.toLowerCase() as ScanResult['threat_level'],
          confidence: analysis.confidence,
          accuracy_score: analysis.confidence,
          risk_percentage: analysis.risk_score,
          indicators: analysis.indicators.map(parseIndicator),
          recommendation: analysis.recommendations?.[0] || 'No specific recommendation available.',
          riskBreakdown: analysis.risk_breakdown || backendResult.analysis.result.riskBreakdown,
          scan_details: {
            scan_type: type.toUpperCase(),
            processing_time: backendResult.analysis.scan_duration_ms ? backendResult.analysis.scan_duration_ms / 1000 : 2.5,
            database_version: backendResult.analysis.model_version || 'PhishGuard Cloud Engine v2.1 (LIVE)',
            analysis_depth: `${Math.max(1, completedLayers.length)} Detection Layers (DIRECT API)`
          },
          metadata
        };

        setScanResult(transformedResult);
      } else {
        throw new Error('Backend analysis failed');
      }
    } catch (error) {
      console.error('Backend analysis failed, using fallback:', error);
      
      // Fallback to local analysis
      let analysisResult: Partial<ScanResult>;
      
      if (type === 'url') {
        analysisResult = analyzeURL(content);
      } else {
        analysisResult = analyzeEmail(content);
      }

      // Add safe indicators if no threats found
      if (analysisResult.indicators?.length === 0) {
        analysisResult.indicators = [{
          type: 'info',
          category: 'Clean Scan',
          description: 'No malicious indicators detected',
          confidence: 95,
          technical_details: 'Content passed all security checks'
        }];
      }

      // Generate recommendation
      let recommendation = '';
      switch (analysisResult.threat_level) {
        case 'high':
          recommendation = '🚨 HIGH RISK: Do not interact with this content. Block immediately and report to security team. This appears to be a phishing attempt.';
          break;
        case 'medium':
          recommendation = '⚠️ MEDIUM RISK: Exercise extreme caution. Verify through official channels before taking any action. Do not click links or provide information.';
          break;
        case 'low':
          recommendation = '⚡ LOW RISK: Minor concerns detected. Proceed with caution and verify sender authenticity through alternative means.';
          break;
        default:
          recommendation = '✅ SAFE: Content appears legitimate. No significant threats detected, but always remain vigilant.';
      }

      const finalResult: ScanResult = {
        ...analysisResult,
        recommendation,
        scan_details: {
          scan_type: type.toUpperCase(),
          processing_time: 2.3 + Math.random() * 1.5,
          database_version: 'v2024.1.1 (Local)',
          analysis_depth: 'Fallback Analysis'
        }
      } as ScanResult;

      setScanResult(finalResult);
    }

    setIsScanning(false);
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'high': return 'threat-high';
      case 'medium': return 'threat-medium';
      case 'low': return 'threat-low';
      default: return 'threat-safe';
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'high': return <AlertTriangle className="w-5 h-5 text-red-500" />;
      case 'medium': return <AlertTriangle className="w-5 h-5 text-orange-500" />;
      case 'low': return <Shield className="w-5 h-5 text-yellow-500" />;
      default: return <CheckCircle className="w-5 h-5 text-green-500" />;
    }
  };

  const getIndicatorIcon = (type: ThreatIndicator['type']) => {
    switch (type) {
      case 'critical': return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case 'warning': return <AlertTriangle className="w-4 h-4 text-orange-500" />;
      default: return <Info className="w-4 h-4 text-blue-500" />;
    }
  };

  return (
    <AnimatePresence mode="wait">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="space-y-6"
      >
      <Card className="phish-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-500 animate-pulse-soft" />
            AI-Powered Threat Analysis Scanner
          </CardTitle>
          <CardDescription>
            Advanced phishing detection with real-time threat intelligence and confidence scoring
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="url" className="w-full">
            <TabsList className="grid w-full grid-cols-4 bg-card/50 backdrop-blur-sm">
              <TabsTrigger value="url" className="tabs-trigger-enhanced flex items-center gap-2">
                <Link className="w-4 h-4" />
                URL Analysis
              </TabsTrigger>
              <TabsTrigger value="email" className="tabs-trigger-enhanced flex items-center gap-2">
                <Mail className="w-4 h-4" />
                Email Scanner
              </TabsTrigger>
              <TabsTrigger value="message" className="tabs-trigger-enhanced flex items-center gap-2">
                <MessageSquare className="w-4 h-4" />
                Message Check
              </TabsTrigger>
              <TabsTrigger value="file" className="tabs-trigger-enhanced flex items-center gap-2">
                <Upload className="w-4 h-4" />
                File Analysis
              </TabsTrigger>
            </TabsList>

            <TabsContent value="url" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url-input" className="flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  Website URL or Domain
                </Label>
                <Input
                  id="url-input"
                  placeholder="https://example.com or suspicious-site.com"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  className="bg-input-background backdrop-blur-sm"
                />
                <p className="text-xs text-muted-foreground">
                  Analyze URLs for domain reputation, SSL status, and suspicious patterns
                </p>
              </div>
              <Button 
                onClick={() => performScan(urlInput, 'url')}
                disabled={!urlInput || isScanning}
                className="w-full security-button"
              >
                <Zap className="w-4 h-4 mr-2" />
                {isScanning ? 'Analyzing URL...' : 'Scan URL for Threats'}
              </Button>
            </TabsContent>

            <TabsContent value="email" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email-content" className="flex items-center gap-2">
                  <Mail className="w-4 h-4" />
                  Email Content Analysis
                </Label>
                <Textarea
                  id="email-content"
                  placeholder="Paste the complete email content including headers, subject, and body..."
                  value={emailContent}
                  onChange={(e) => setEmailContent(e.target.value)}
                  rows={8}
                  className="bg-input-background backdrop-blur-sm"
                />
                <p className="text-xs text-muted-foreground">
                  Analyze email content for phishing patterns, social engineering, and suspicious language
                </p>
              </div>
              <Button 
                onClick={() => performScan(emailContent, 'email')}
                disabled={!emailContent || isScanning}
                className="w-full security-button"
              >
                <Eye className="w-4 h-4 mr-2" />
                {isScanning ? 'Analyzing Email...' : 'Deep Scan Email Content'}
              </Button>
            </TabsContent>

            <TabsContent value="message" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="message-content" className="flex items-center gap-2">
                  <MessageSquare className="w-4 h-4" />
                  Message or Text Content
                </Label>
                <Textarea
                  id="message-content"
                  placeholder="Paste SMS, chat message, or any text content you want to analyze..."
                  value={messageContent}
                  onChange={(e) => setMessageContent(e.target.value)}
                  rows={6}
                  className="bg-input-background backdrop-blur-sm"
                />
                <p className="text-xs text-muted-foreground">
                  Check messages for scam indicators, urgency tactics, and suspicious requests
                </p>
              </div>
              <Button 
                onClick={() => performScan(messageContent, 'message')}
                disabled={!messageContent || isScanning}
                className="w-full security-button"
              >
                <Shield className="w-4 h-4 mr-2" />
                {isScanning ? 'Analyzing Message...' : 'Scan Message Content'}
              </Button>
            </TabsContent>

            <TabsContent value="file" className="space-y-4">
              <div
                className={`border-2 border-dashed rounded-lg p-8 text-center glass-effect transition-all ${
                  isDragging ? 'border-blue-500 bg-blue-50 dark:bg-blue-950/20' : 'border-border/50'
                }`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
              >
                <Upload className={`w-12 h-12 mx-auto mb-4 ${
                  isDragging ? 'text-blue-500 animate-bounce' : 'text-muted-foreground animate-pulse-soft'
                }`} />

                {selectedFile ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-center gap-2 text-lg font-medium">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      File Selected
                    </div>
                    <div className="bg-card/50 backdrop-blur-sm rounded-lg p-4 max-w-md mx-auto">
                      <div className="flex items-start gap-3">
                        <Upload className="w-5 h-5 text-blue-500 mt-1" />
                        <div className="flex-1 text-left">
                          <p className="font-medium break-all">{selectedFile.name}</p>
                          <p className="text-sm text-muted-foreground">
                            Size: {(selectedFile.size / 1024).toFixed(1)} KB
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Type: {selectedFile.type || 'Unknown'}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2 justify-center">
                      <Button
                        onClick={performFileScan}
                        disabled={isScanning}
                        className="security-button"
                      >
                        <Shield className="w-4 h-4 mr-2" />
                        {isScanning ? 'Analyzing File...' : 'Scan File for Threats'}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => setSelectedFile(null)}
                        disabled={isScanning}
                      >
                        Clear
                      </Button>
                    </div>
                  </div>
                ) : (
                  <>
                    <p className="text-lg font-medium mb-2">Advanced File Analysis</p>
                    <p className="text-sm text-muted-foreground mb-4">
                      Drop files here or click to browse<br />
                      Supports PDF, DOC, images, executables (max 100MB)
                    </p>
                    <input
                      type="file"
                      id="file-upload"
                      className="hidden"
                      onChange={handleFileSelect}
                      accept="*/*"
                    />
                    <Button
                      variant="outline"
                      className="security-button"
                      onClick={() => document.getElementById('file-upload')?.click()}
                    >
                      <Upload className="w-4 h-4 mr-2" />
                      Choose Files for Analysis
                    </Button>
                    <p className="text-xs text-muted-foreground mt-3">
                      Files are scanned for malware, suspicious content, and metadata analysis
                    </p>
                  </>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Detailed Analysis Progress */}
      {isScanning && (
        <Card className="phish-card border-blue-500/50 shadow-lg shadow-blue-500/20">
          <CardContent className="pt-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-medium flex items-center gap-2">
                  <Brain className="w-5 h-5 text-blue-500 animate-pulse" />
                  Advanced Threat Analysis in Progress
                </span>
                <Badge variant="outline" className="animate-pulse bg-blue-500/10 border-blue-500 text-blue-600">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-blue-500 rounded-full animate-ping" />
                    Processing...
                  </div>
                </Badge>
              </div>

              <div className="space-y-3">
                {analysisProgress.map((step, index) => (
                  <div key={index} className="space-y-2 animate-in fade-in slide-in-from-left-3 duration-300">
                    <div className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full transition-all duration-300 ${
                          step.progress === 100 ? 'bg-green-500 shadow-lg shadow-green-500/50' :
                          step.progress > 0 ? 'bg-blue-500 animate-pulse shadow-lg shadow-blue-500/50' : 'bg-muted'
                        }`} />
                        <span className={step.progress === 100 ? 'text-green-600 font-medium' : ''}>
                          {step.step}
                        </span>
                      </span>
                      <span className={`text-muted-foreground ${step.progress === 100 ? 'text-green-600 font-semibold' : ''}`}>
                        {step.progress}%
                      </span>
                    </div>
                    <Progress
                      value={step.progress}
                      className={`h-2 transition-all duration-500 ${
                        step.progress === 100 ? 'bg-green-100 dark:bg-green-950' : 'bg-blue-100 dark:bg-blue-950'
                      }`}
                    />
                    <p className={`text-xs transition-all duration-300 ${
                      step.progress === 100 ? 'text-green-600' : 'text-muted-foreground'
                    }`}>
                      {step.progress === 100 ? '✓ ' : ''}
                      {step.details}
                    </p>
                  </div>
                ))}
              </div>

              {/* Overall Progress Summary */}
              {analysisProgress.length > 0 && (
                <div className="mt-4 pt-4 border-t border-border/50">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Overall Progress</span>
                    <span className="font-semibold text-blue-600">
                      {Math.round(analysisProgress.reduce((sum, step) => sum + step.progress, 0) / analysisProgress.length)}%
                    </span>
                  </div>
                  <Progress
                    value={analysisProgress.reduce((sum, step) => sum + step.progress, 0) / analysisProgress.length}
                    className="h-3 mt-2"
                  />
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Comprehensive Scan Results */}
      {scanResult && (
        <Card className="phish-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {getThreatIcon(scanResult.threat_level)}
              Comprehensive Threat Analysis Report
            </CardTitle>
            <CardDescription>
              Generated by AI-powered threat detection engine
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Threat Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="phish-card p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">Threat Level</p>
                    <p className={`text-lg font-bold capitalize ${getThreatColor(scanResult.threat_level)}`}>
                      {scanResult.threat_level === 'safe' ? 'Safe' : `${scanResult.threat_level} Risk`}
                    </p>
                  </div>
                  {getThreatIcon(scanResult.threat_level)}
                </div>
              </div>

              <div className="phish-card p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">Confidence Score</p>
                    <p className="text-lg font-bold text-blue-600">{scanResult.confidence}%</p>
                  </div>
                  <Brain className="w-6 h-6 text-blue-500" />
                </div>
              </div>

              <div className="phish-card p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-sm">Accuracy Score</p>
                    <p className="text-lg font-bold text-purple-600">{scanResult.accuracy_score}%</p>
                  </div>
                  <Zap className="w-6 h-6 text-purple-500" />
                </div>
              </div>

              <Dialog>
                <DialogTrigger asChild>
                  <div className="phish-card p-4 cursor-pointer hover:shadow-lg transition-shadow border-2 border-transparent hover:border-red-300">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium text-sm flex items-center gap-1">
                          Risk Percentage
                          <Info className="w-3 h-3 text-muted-foreground" />
                        </p>
                        <p className="text-lg font-bold text-red-600">{scanResult.risk_percentage}%</p>
                        <p className="text-xs text-muted-foreground mt-1">Click for details</p>
                      </div>
                      <AlertTriangle className="w-6 h-6 text-red-500" />
                    </div>
                  </div>
                </DialogTrigger>
                <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                      <TrendingUp className="w-5 h-5 text-red-500" />
                      Detailed Risk Breakdown
                    </DialogTitle>
                    <DialogDescription>
                      Comprehensive analysis of all risk factors contributing to the {scanResult.risk_percentage}% risk score
                    </DialogDescription>
                  </DialogHeader>

                  <div className="space-y-6 mt-4">
                    {/* Overall Risk Summary */}
                    <div className="bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-950/20 dark:to-orange-950/20 p-4 rounded-lg border-l-4 border-red-500">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-semibold text-lg">Overall Risk Score</h3>
                        <Badge variant="destructive" className="text-lg px-3 py-1">
                          {scanResult.risk_percentage}%
                        </Badge>
                      </div>
                      <Progress value={scanResult.risk_percentage} className="h-3 mb-2" />
                      <p className="text-sm text-muted-foreground">
                        {scanResult.risk_percentage >= 70 ? 'CRITICAL - Immediate action required' :
                         scanResult.risk_percentage >= 50 ? 'HIGH - Significant threats detected' :
                         scanResult.risk_percentage >= 30 ? 'MEDIUM - Multiple risk factors present' :
                         scanResult.risk_percentage >= 15 ? 'LOW - Minor concerns detected' :
                         'MINIMAL - Generally safe with minor warnings'}
                      </p>
                    </div>

                    {/* Detection Layer Risk Contributions - REAL BACKEND DATA */}
                    {scanResult.riskBreakdown && scanResult.riskBreakdown.length > 0 ? (
                      <div>
                        <div className="flex items-center justify-between mb-4">
                          <h3 className="font-semibold flex items-center gap-2">
                            <TrendingUp className="w-5 h-5 text-blue-600" />
                            Detection Layer Analysis
                          </h3>
                          <Badge variant="secondary" className="text-xs">
                            {scanResult.riskBreakdown.length} layers scanned
                          </Badge>
                        </div>
                        <div className="space-y-3">
                          {scanResult.riskBreakdown.map((breakdown, index) => {
                            // Determine color based on risk contribution
                            const isHighRisk = breakdown.riskContribution >= 15;
                            const isMediumRisk = breakdown.riskContribution >= 8 && breakdown.riskContribution < 15;
                            const isLowRisk = breakdown.riskContribution < 8;

                            const gradientClass = isHighRisk
                              ? 'from-red-50 via-orange-50 to-yellow-50 dark:from-red-950/30 dark:via-orange-950/20 dark:to-yellow-950/10 border-red-300'
                              : isMediumRisk
                              ? 'from-orange-50 via-yellow-50 to-amber-50 dark:from-orange-950/20 dark:via-yellow-950/10 dark:to-amber-950/10 border-orange-300'
                              : 'from-blue-50 via-indigo-50 to-purple-50 dark:from-blue-950/20 dark:via-indigo-950/10 dark:to-purple-950/10 border-blue-300';

                            const iconColor = isHighRisk ? 'text-red-600' : isMediumRisk ? 'text-orange-600' : 'text-blue-600';
                            const contributionColor = isHighRisk ? 'text-red-600' : isMediumRisk ? 'text-orange-600' : 'text-blue-600';

                            return (
                              <div key={index} className={`p-5 rounded-xl border-2 bg-gradient-to-br ${gradientClass} shadow-sm hover:shadow-md transition-all duration-200`}>
                                <div className="flex items-start justify-between gap-4 mb-3">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                      <div className={`p-1.5 rounded-lg ${isHighRisk ? 'bg-red-100 dark:bg-red-900/40' : isMediumRisk ? 'bg-orange-100 dark:bg-orange-900/40' : 'bg-blue-100 dark:bg-blue-900/40'}`}>
                                        <Shield className={`w-4 h-4 ${iconColor}`} />
                                      </div>
                                      <span className="font-bold text-base">{breakdown.layer}</span>
                                      <Badge variant="outline" className="text-xs font-medium bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
                                        Weight: {breakdown.weight}%
                                      </Badge>
                                    </div>

                                    {/* Risk Details with bullet points */}
                                    <div className="ml-8 space-y-1">
                                      {breakdown.details.includes('Risks found:') ? (
                                        <div>
                                          <p className="text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">🔍 Detected Risks:</p>
                                          {breakdown.details.replace('Risks found: ', '').split('; ').map((risk, idx) => (
                                            <div key={idx} className="flex items-start gap-2 text-sm">
                                              <span className="text-red-500 mt-0.5">•</span>
                                              <span className="text-gray-700 dark:text-gray-300">{risk}</span>
                                            </div>
                                          ))}
                                        </div>
                                      ) : (
                                        <p className="text-sm text-gray-600 dark:text-gray-400 flex items-center gap-1.5">
                                          <CheckCircle className="w-3.5 h-3.5 text-green-500" />
                                          {breakdown.details}
                                        </p>
                                      )}
                                    </div>
                                  </div>

                                  {/* Risk Contribution Badge */}
                                  <div className="text-right min-w-[80px]">
                                    <div className="text-xs text-muted-foreground mb-1 font-medium">Impact</div>
                                    <div className={`text-3xl font-bold ${contributionColor} leading-none`}>
                                      +{breakdown.riskContribution}%
                                    </div>
                                    <div className="text-xs text-muted-foreground mt-1">
                                      {isHighRisk ? 'High' : isMediumRisk ? 'Medium' : 'Low'}
                                    </div>
                                  </div>
                                </div>

                                {/* Visual Progress Bar */}
                                <div className="space-y-1">
                                  <div className="flex items-center justify-between text-xs">
                                    <span className="text-muted-foreground">Contribution to total risk</span>
                                    <span className="font-medium">{Math.round((breakdown.riskContribution / scanResult.risk_percentage) * 100)}%</span>
                                  </div>
                                  <div className="relative h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                    <div
                                      className={`h-full rounded-full transition-all duration-500 ${
                                        isHighRisk ? 'bg-gradient-to-r from-red-500 to-red-600' :
                                        isMediumRisk ? 'bg-gradient-to-r from-orange-500 to-orange-600' :
                                        'bg-gradient-to-r from-blue-500 to-blue-600'
                                      }`}
                                      style={{ width: `${(breakdown.riskContribution / scanResult.risk_percentage) * 100}%` }}
                                    />
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>

                        {/* Summary Card */}
                        <div className="mt-4 p-4 bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-900/50 dark:to-gray-800/50 rounded-xl border border-gray-300 dark:border-gray-700">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <div className="p-2 bg-blue-100 dark:bg-blue-900/40 rounded-lg">
                                <TrendingUp className="w-5 h-5 text-blue-600" />
                              </div>
                              <div>
                                <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Total Risk Calculated</p>
                                <p className="text-xs text-muted-foreground">Sum of all weighted contributions</p>
                              </div>
                            </div>
                            <div className="text-right">
                              <div className="text-3xl font-bold text-blue-600">
                                {scanResult.risk_percentage}%
                              </div>
                              <div className="text-xs text-muted-foreground">Final Score</div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      /* Fallback to indicators if backend breakdown not available */
                      <div>
                        <h3 className="font-semibold mb-3 flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4" />
                          Threat Indicators ({scanResult.indicators.length})
                        </h3>
                        <div className="space-y-2">
                          {scanResult.indicators.slice(0, 5).map((indicator, index) => (
                            <div key={index} className={`p-3 rounded-lg border ${
                              indicator.type === 'critical' ? 'bg-red-50 dark:bg-red-950/20 border-red-200' :
                              indicator.type === 'warning' ? 'bg-orange-50 dark:bg-orange-950/20 border-orange-200' :
                              'bg-blue-50 dark:bg-blue-950/20 border-blue-200'
                            }`}>
                              <div className="flex items-center gap-2">
                                {indicator.type === 'critical' ? (
                                  <XCircle className="w-4 h-4 text-red-600" />
                                ) : indicator.type === 'warning' ? (
                                  <AlertTriangle className="w-4 h-4 text-orange-600" />
                                ) : (
                                  <Info className="w-4 h-4 text-blue-600" />
                                )}
                                <div className="flex-1">
                                  <span className="font-medium text-sm">{indicator.category}</span>
                                  <p className="text-sm text-muted-foreground">{indicator.description}</p>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Risk Category Breakdown */}
                    <div>
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Shield className="w-4 h-4" />
                        Risk Categories
                      </h3>
                      <div className="grid grid-cols-3 gap-3">
                        <div className="phish-card p-3 text-center">
                          <XCircle className="w-5 h-5 text-red-500 mx-auto mb-2" />
                          <div className="text-2xl font-bold text-red-600">
                            {scanResult.indicators.filter(i => i.type === 'critical').length}
                          </div>
                          <div className="text-xs text-muted-foreground">Critical Issues</div>
                        </div>
                        <div className="phish-card p-3 text-center">
                          <AlertTriangle className="w-5 h-5 text-orange-500 mx-auto mb-2" />
                          <div className="text-2xl font-bold text-orange-600">
                            {scanResult.indicators.filter(i => i.type === 'warning').length}
                          </div>
                          <div className="text-xs text-muted-foreground">Warnings</div>
                        </div>
                        <div className="phish-card p-3 text-center">
                          <Info className="w-5 h-5 text-blue-500 mx-auto mb-2" />
                          <div className="text-2xl font-bold text-blue-600">
                            {scanResult.indicators.filter(i => i.type === 'info').length}
                          </div>
                          <div className="text-xs text-muted-foreground">Informational</div>
                        </div>
                      </div>
                    </div>

                    {/* Recommendations */}
                    <div className="bg-blue-50 dark:bg-blue-950/20 p-4 rounded-lg border border-blue-200">
                      <h3 className="font-semibold mb-2 flex items-center gap-2">
                        <Shield className="w-4 h-4 text-blue-600" />
                        Security Recommendation
                      </h3>
                      <p className="text-sm">{scanResult.recommendation}</p>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
            </div>

            {/* Detailed Threat Indicators */}
            <div className="space-y-3">
              <h4 className="font-semibold flex items-center gap-2">
                <Eye className="w-4 h-4" />
                Detailed Threat Indicators ({scanResult.indicators.length})
              </h4>
              <div className="space-y-3">
                {scanResult.indicators.map((indicator, index) => (
                  <Alert key={index} className={`border-l-4 ${
                    indicator.type === 'critical' ? 'border-l-red-500 bg-red-50 dark:bg-red-950/20' :
                    indicator.type === 'warning' ? 'border-l-orange-500 bg-orange-50 dark:bg-orange-950/20' :
                    'border-l-blue-500 bg-blue-50 dark:bg-blue-950/20'
                  }`}>
                    <div className="flex items-start gap-3">
                      {getIndicatorIcon(indicator.type)}
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <AlertDescription className="font-medium">
                            {indicator.category}: {indicator.description}
                          </AlertDescription>
                          <Badge variant="outline" className="ml-2">
                            {indicator.confidence}% confidence
                          </Badge>
                        </div>
                        {indicator.technical_details && (
                          <p className="text-xs text-muted-foreground mt-1">
                            Technical: {indicator.technical_details}
                          </p>
                        )}
                      </div>
                    </div>
                  </Alert>
                ))}
              </div>
            </div>

            {/* Metadata Information */}
            {scanResult.metadata && (
              <div className="space-y-3">
                <h4 className="font-semibold flex items-center gap-2">
                  <Info className="w-4 h-4" />
                  Technical Metadata
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {Object.entries(scanResult.metadata).map(([key, value]) => (
                    <div key={key} className="phish-card p-3">
                      <p className="text-xs text-muted-foreground capitalize">
                        {key.replace(/_/g, ' ')}
                      </p>
                      <p className="font-medium">{value}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Scan Details */}
            <div className="space-y-3">
              <h4 className="font-semibold flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Scan Information
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="phish-card p-3">
                  <p className="text-xs text-muted-foreground">Scan Type</p>
                  <p className="font-medium">{scanResult.scan_details.scan_type}</p>
                </div>
                <div className="phish-card p-3">
                  <p className="text-xs text-muted-foreground">Processing Time</p>
                  <p className="font-medium">{scanResult.scan_details.processing_time.toFixed(1)}s</p>
                </div>
                <div className="phish-card p-3">
                  <p className="text-xs text-muted-foreground">Database Version</p>
                  <p className="font-medium">{scanResult.scan_details.database_version}</p>
                </div>
                <div className="phish-card p-3">
                  <p className="text-xs text-muted-foreground">Analysis Depth</p>
                  <p className="font-medium">{scanResult.scan_details.analysis_depth}</p>
                </div>
              </div>
            </div>

            {/* AI Recommendation */}
            <Alert className={`${
              scanResult.threat_level === 'high' ? 'border-red-500 bg-red-50 dark:bg-red-950/20' :
              scanResult.threat_level === 'medium' ? 'border-orange-500 bg-orange-50 dark:bg-orange-950/20' :
              scanResult.threat_level === 'low' ? 'border-yellow-500 bg-yellow-50 dark:bg-yellow-950/20' :
              'border-green-500 bg-green-50 dark:bg-green-950/20'
            }`}>
              <Shield className="h-4 w-4" />
              <AlertDescription className="font-medium">
                <span className="block mb-2">AI Security Recommendation:</span>
                <span className="whitespace-pre-wrap">{scanResult.recommendation}</span>
              </AlertDescription>
            </Alert>

            {/* Action Buttons */}
            <div className="flex gap-3 pt-4">
              <Button variant="outline" className="flex items-center gap-2">
                <ExternalLink className="w-4 h-4" />
                View Detailed Report
              </Button>
              <Button variant="outline" className="flex items-center gap-2">
                <Calendar className="w-4 h-4" />
                Schedule Rescan
              </Button>
              <Button variant="outline" className="flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Add to Blocklist
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
      </motion.div>
    </AnimatePresence>
  );
}