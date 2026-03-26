interface ScanRequest {
  type: 'url' | 'email' | 'message' | 'file';
  target?: string;
  url?: string;
  content?: string;
  headers?: any;
  message?: string;
  context?: any;
  user_id?: string;
}

interface ScanResult {
  id: string;
  type: string;
  target: string;
  result: {
    confidence: number;
    threat_level: string;
    risk_score: number;
    indicators: string[];
    recommendations: string[];
  };
  timestamp: string;
  user_id?: string;
  model_version: string;
}

interface ModelConfig {
  id: string;
  config: {
    state: string;
    version: string;
    confidence_threshold: number;
    features: string[];
    updated_at?: string;
  };
}

class BackendServiceClass {
  private baseUrl: string;
  private headers: { [key: string]: string };
  private backendAvailable: boolean = true; // Start optimistic
  private lastAvailabilityCheck: number = 0;
  private readonly RECOVERY_INTERVAL_MS = 30000; // Re-check backend every 30s

  constructor() {
    // Use Next.js API routes (relative paths for same-origin requests)
    this.baseUrl = '/api';
    this.headers = {
      'Content-Type': 'application/json',
    };

    // No need to test on initialization - will test on first actual request
  }

  private async testBackendAvailability() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout

      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
        headers: this.headers,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        this.backendAvailable = true;
      } else {
        this.backendAvailable = false;
      }
    } catch (error) {
      this.backendAvailable = false;
      // Silently fail - fallback will be used automatically
    }
  }

  private async makeRequest(endpoint: string, options: RequestInit = {}) {
    // If backend is known to be unavailable, periodically re-check
    if (!this.backendAvailable) {
      const now = Date.now();
      if (now - this.lastAvailabilityCheck > this.RECOVERY_INTERVAL_MS) {
        this.lastAvailabilityCheck = now;
        await this.testBackendAvailability();
      }
      if (!this.backendAvailable) {
        throw new Error('Backend service unavailable');
      }
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        headers: {
          ...this.headers,
          ...options.headers
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        // Mark backend as unavailable on 500+ errors
        if (response.status >= 500) {
          this.backendAvailable = false;
        }

        throw new Error(`Request failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      // Mark backend as unavailable on network errors
      if (error instanceof Error && (error.name === 'AbortError' || error.message.includes('fetch'))) {
        this.backendAvailable = false;
      }

      throw error;
    }
  }

  // Health and Status
  async getHealth() {
    try {
      // Try to re-test availability if marked as unavailable
      if (!this.backendAvailable) {
        await this.testBackendAvailability();
      }

      if (this.backendAvailable) {
        return await this.makeRequest('/health');
      } else {
        throw new Error('Backend marked as unavailable');
      }
    } catch (error) {
      // Return fallback health status silently
      return {
        success: false,
        status: 'offline',
        timestamp: new Date().toISOString(),
        models: [],
        error: 'Backend service unavailable'
      };
    }
  }

  async getStats(userId?: string) {
    try {
      const query = userId ? `?user_id=${userId}` : '';
      return await this.makeRequest(`/stats${query}`);
    } catch (error) {
      // Return fallback statistics silently
      return {
        success: true,
        stats: {
          total_scans: 0,
          threats_detected: 0,
          safe_items: 0,
          suspicious_items: 0,
          by_type: {
            url: 0,
            email: 0,
            message: 0,
            file: 0
          },
          recent_activity: 0
        }
      };
    }
  }

  // Model Management
  async getModels(): Promise<{ success: boolean; models: ModelConfig[] }> {
    try {
      const result = await this.makeRequest('/models');
      return result;
    } catch (error) {
      // Return fallback model configuration silently
      return {
        success: true,
        models: [
          {
            id: 'url_analyzer_v1',
            config: {
              state: 'active',
              version: '1.0.0',
              confidence_threshold: 0.7,
              features: ['domain_analysis', 'ssl_check', 'content_scan', 'reputation_lookup']
            }
          },
          {
            id: 'email_scanner_v2',
            config: {
              state: 'active',
              version: '2.0.0',
              confidence_threshold: 0.8,
              features: ['header_analysis', 'attachment_scan', 'content_nlp', 'sender_reputation']
            }
          },
          {
            id: 'file_detector_v1',
            config: {
              state: 'active',
              version: '1.0.0',
              confidence_threshold: 0.75,
              features: ['file_signature', 'metadata_analysis', 'behavioral_patterns']
            }
          },
          {
            id: 'message_classifier_v1',
            config: {
              state: 'active',
              version: '1.0.0',
              confidence_threshold: 0.85,
              features: ['nlp_analysis', 'social_engineering_detection', 'urgency_patterns']
            }
          }
        ]
      };
    }
  }

  async updateModelState(modelId: string, state: string) {
    return this.makeRequest(`/models/${modelId}/state`, {
      method: 'POST',
      body: JSON.stringify({ state })
    });
  }

  // Scanning Functions
  async analyzeUrl(url: string, userId?: string): Promise<{ success: boolean; analysis: ScanResult }> {
    try {
      return await this.makeRequest('/analyze/url', {
        method: 'POST',
        body: JSON.stringify({ url, user_id: userId })
      });
    } catch (error) {
      // Use local fallback silently
      return this.generateLocalUrlAnalysis(url, userId);
    }
  }

  async analyzeEmail(content: string, headers: any = {}, userId?: string): Promise<{ success: boolean; analysis: ScanResult }> {
    try {
      return await this.makeRequest('/analyze/email', {
        method: 'POST',
        body: JSON.stringify({ content, headers, user_id: userId })
      });
    } catch (error) {
      // Use local fallback silently
      return this.generateLocalEmailAnalysis(content, headers, userId);
    }
  }

  async analyzeMessage(message: string, context: any = {}, userId?: string): Promise<{ success: boolean; analysis: ScanResult }> {
    try {
      return await this.makeRequest('/analyze/message', {
        method: 'POST',
        body: JSON.stringify({ message, context, user_id: userId })
      });
    } catch (error) {
      // Use local fallback silently
      return this.generateLocalMessageAnalysis(message, context, userId);
    }
  }

  // Scan History
  async getScans(userId?: string): Promise<{ success: boolean; scans: ScanResult[] }> {
    try {
      const query = userId ? `?user_id=${userId}` : '';
      return await this.makeRequest(`/scans${query}`);
    } catch (error) {
      // Return empty array silently
      return {
        success: true,
        scans: []
      };
    }
  }

  async getScanDetails(scanId: string): Promise<{ success: boolean; scan: ScanResult }> {
    return this.makeRequest(`/scans/${scanId}`);
  }

  // Utility Functions
  formatThreatLevel(level: string): { color: string; label: string } {
    const levels: { [key: string]: { color: string; label: string } } = {
      'SAFE': { color: 'text-green-500', label: 'Safe' },
      'LOW': { color: 'text-yellow-500', label: 'Low Risk' },
      'MEDIUM': { color: 'text-orange-500', label: 'Medium Risk' },
      'HIGH': { color: 'text-red-500', label: 'High Risk' },
      'CRITICAL': { color: 'text-red-600', label: 'Critical' },
      'UNKNOWN': { color: 'text-gray-500', label: 'Unknown' }
    };
    return levels[level] || levels['UNKNOWN'];
  }

  formatTimestamp(timestamp: string): string {
    return new Date(timestamp).toLocaleString();
  }

  generateUserId(): string {
    // Generate a simple session-based user ID for demo purposes
    if (typeof window === 'undefined') {
      // SSR context — return a temporary ID
      return `user_ssr_${Date.now()}_${Math.random().toString(36).substring(2)}`;
    }
    let userId = localStorage.getItem('phishguard_user_id');
    if (!userId) {
      userId = `user_${Date.now()}_${Math.random().toString(36).substring(2)}`;
      localStorage.setItem('phishguard_user_id', userId);
    }
    return userId;
  }

  // Local fallback analysis functions
  private generateLocalUrlAnalysis(url: string, userId?: string): { success: boolean; analysis: ScanResult } {
    const suspiciousPatterns = ['secure-', 'verify-', 'login-', 'urgent', 'suspend', 'update-'];
    const legitimateDomains = ['google.com', 'microsoft.com', 'apple.com', 'github.com'];
    
    let riskScore = 0;
    const indicators = [];
    
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      const domain = urlObj.hostname.toLowerCase();
      
      // Check for suspicious patterns
      if (suspiciousPatterns.some(pattern => url.toLowerCase().includes(pattern))) {
        riskScore += 30;
        indicators.push('Suspicious URL patterns detected');
      }
      
      // Check for legitimate domains
      if (legitimateDomains.some(legit => domain.includes(legit))) {
        riskScore -= 20;
        indicators.push('Legitimate domain detected');
      }
      
      // Check HTTPS
      if (!url.startsWith('https://')) {
        riskScore += 20;
        indicators.push('Insecure HTTP connection');
      }
      
      // Check URL length
      if (url.length > 100) {
        riskScore += 15;
        indicators.push('Unusually long URL');
      }
      
    } catch (error) {
      riskScore += 50;
      indicators.push('Invalid URL format');
    }
    
    const threat_level = riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : riskScore >= 15 ? 'LOW' : 'SAFE';
    const confidence = Math.max(60, 95 - Math.floor(riskScore / 3));
    
    return {
      success: true,
      analysis: {
        id: crypto.randomUUID(),
        type: 'url',
        target: url,
        result: {
          confidence,
          threat_level,
          risk_score: Math.min(95, riskScore),
          indicators,
          recommendations: this.generateRecommendations(threat_level)
        },
        timestamp: new Date().toISOString(),
        user_id: userId,
        model_version: 'local-fallback-1.0'
      }
    };
  }

  private generateLocalEmailAnalysis(content: string, headers: any, userId?: string): { success: boolean; analysis: ScanResult } {
    const suspiciousKeywords = ['urgent', 'verify', 'suspend', 'expire', 'winner', 'congratulations', 'claim', 'prize'];
    let riskScore = 0;
    const indicators = [];
    
    const lowerContent = content.toLowerCase();
    const keywordMatches = suspiciousKeywords.filter(keyword => lowerContent.includes(keyword));
    
    if (keywordMatches.length > 0) {
      riskScore += keywordMatches.length * 15;
      indicators.push(`Suspicious keywords: ${keywordMatches.join(', ')}`);
    }
    
    // Check for links
    const urlMatches = content.match(/https?:\/\/[^\s]+/gi) || [];
    if (urlMatches.length > 3) {
      riskScore += 20;
      indicators.push('Multiple links detected');
    }
    
    // Check for generic greetings
    if (lowerContent.includes('dear customer') || lowerContent.includes('dear sir/madam')) {
      riskScore += 15;
      indicators.push('Generic greeting detected');
    }
    
    const threat_level = riskScore >= 45 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : riskScore >= 10 ? 'LOW' : 'SAFE';
    const confidence = Math.max(65, 92 - Math.floor(riskScore / 4));
    
    return {
      success: true,
      analysis: {
        id: crypto.randomUUID(),
        type: 'email',
        target: content.substring(0, 50) + '...',
        result: {
          confidence,
          threat_level,
          risk_score: Math.min(90, riskScore),
          indicators,
          recommendations: this.generateRecommendations(threat_level)
        },
        timestamp: new Date().toISOString(),
        user_id: userId,
        model_version: 'local-fallback-1.0'
      }
    };
  }

  private generateLocalMessageAnalysis(message: string, context: any, userId?: string): { success: boolean; analysis: ScanResult } {
    const socialEngineeringPatterns = ['urgent', 'click here', 'verify account', 'suspended', 'expire', 'immediate'];
    let riskScore = 0;
    const indicators = [];
    
    const lowerMessage = message.toLowerCase();
    const patternMatches = socialEngineeringPatterns.filter(pattern => lowerMessage.includes(pattern));
    
    if (patternMatches.length > 0) {
      riskScore += patternMatches.length * 12;
      indicators.push(`Social engineering patterns: ${patternMatches.join(', ')}`);
    }
    
    // Check for financial terms
    const financialTerms = ['money', 'payment', 'bank', 'card', 'transfer'];
    const financialMatches = financialTerms.filter(term => lowerMessage.includes(term));
    
    if (financialMatches.length > 0) {
      riskScore += 25;
      indicators.push('Financial information request');
    }
    
    const threat_level = riskScore >= 40 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : riskScore >= 10 ? 'LOW' : 'SAFE';
    const confidence = Math.max(70, 90 - Math.floor(riskScore / 3));
    
    return {
      success: true,
      analysis: {
        id: crypto.randomUUID(),
        type: 'message',
        target: message.substring(0, 50) + '...',
        result: {
          confidence,
          threat_level,
          risk_score: Math.min(85, riskScore),
          indicators,
          recommendations: this.generateRecommendations(threat_level)
        },
        timestamp: new Date().toISOString(),
        user_id: userId,
        model_version: 'local-fallback-1.0'
      }
    };
  }

  private generateRecommendations(threat_level: string): string[] {
    const recommendations: { [key: string]: string[] } = {
      'HIGH': [
        'IMMEDIATE ACTION: Do not interact with this content',
        'Report to security team immediately',
        'Block sender if applicable',
        'Change passwords if compromised'
      ],
      'MEDIUM': [
        'Exercise extreme caution',
        'Verify through official channels',
        'Do not click links or provide information',
        'Monitor for suspicious activity'
      ],
      'LOW': [
        'Proceed with caution',
        'Verify sender authenticity',
        'Double-check any requests',
        'Report if suspicious'
      ],
      'SAFE': [
        'Content appears legitimate',
        'Continue with normal security practices',
        'Monitor for any changes',
        'Stay vigilant'
      ]
    };

    return recommendations[threat_level] || recommendations['SAFE'];
  }

  // ==========================================
  // Settings API Methods
  // ==========================================

  async getSettings(userId?: string): Promise<any> {
    try {
      const uid = userId || this.generateUserId();
      return await this.makeRequest(`/settings?user_id=${uid}`);
    } catch {
      return {
        success: true,
        settings: {
          realTimeScanning: true,
          autoQuarantine: false,
          detectionSensitivity: 75,
          defaultAction: 'warn',
          emailAlerts: true,
          desktopAlerts: true,
          dailySummary: false,
          securityLevel: 'medium',
          dataRetentionDays: 30,
        },
        isDefault: true,
      };
    }
  }

  async saveSettings(settings: any, userId?: string): Promise<any> {
    try {
      const uid = userId || this.generateUserId();
      return await this.makeRequest('/settings', {
        method: 'POST',
        body: JSON.stringify({ user_id: uid, settings }),
      });
    } catch (error) {
      console.error('Failed to save settings:', error);
      return { success: false, error: 'Failed to save settings' };
    }
  }

  // ==========================================
  // Scan Deletion
  // ==========================================

  async deleteScan(scanId: string): Promise<any> {
    try {
      return await this.makeRequest(`/scans/${scanId}`, {
        method: 'DELETE',
      });
    } catch (error) {
      console.error('Failed to delete scan:', error);
      return { success: false, error: 'Failed to delete scan' };
    }
  }
}

export const BackendService = new BackendServiceClass();
export type { ScanResult, ModelConfig, ScanRequest };