/**
 * IP Intelligence Service
 *
 * No geolocation or IP-reputation provider is configured, so this service
 * does NOT invent such data: geolocation/network/reputation are left
 * undefined and `dataAvailable` is false (the layer then adds no risk and
 * no confidence). What it does check for real: whether the address is
 * private/internal (loopback, RFC1918, link-local, CGNAT, …).
 */

import { isIP } from 'net';
import { isNonPublicIp } from '@/lib/netGuard';

export interface IPAnalysisResult {
  ipAddress: string;
  riskScore: number; // 0-100
  indicators: string[];
  /** False when no reputation/geolocation data source produced data */
  dataAvailable: boolean;
  isPrivate: boolean;
  note?: string;
  geolocation?: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
  };
  network?: {
    asn?: string;
    asnOrg?: string;
    isp?: string;
    organization?: string;
  };
  reputation?: {
    abuseScore: number; // 0-100
    threatScore: number; // 0-100
    isProxy: boolean;
    isVPN: boolean;
    isTor: boolean;
    isDataCenter: boolean;
    isHosting: boolean;
    isBlacklisted: boolean;
    blacklistCount: number;
    isBot: boolean;
  };
}

const NOT_AVAILABLE_NOTE = 'IP geolocation and reputation data are not available (no provider configured)';

export class IPService {
  /**
   * Analyze IP address
   */
  static async analyze(ipAddress: string): Promise<IPAnalysisResult> {
    const ip = (ipAddress || '').trim().replace(/^\[(.*)\]$/, '$1');

    if (!this.isValidIP(ip)) {
      return {
        ipAddress,
        riskScore: 0,
        indicators: ['Invalid IP address format'],
        dataAvailable: false,
        isPrivate: false,
      };
    }

    if (isNonPublicIp(ip)) {
      // A real, checkable fact — this is what we can say with certainty
      return {
        ipAddress: ip,
        riskScore: 70,
        indicators: ['Points to a private/internal network address'],
        dataAvailable: true,
        isPrivate: true,
        note: 'Private/internal addresses are never sent to external services',
      };
    }

    return {
      ipAddress: ip,
      riskScore: 0,
      indicators: [],
      dataAvailable: false,
      isPrivate: false,
      note: NOT_AVAILABLE_NOTE,
    };
  }

  private static isValidIP(ipAddress: string): boolean {
    return isIP(ipAddress) !== 0;
  }

  static extractIPFromURL(url: string): string | null {
    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.replace(/^\[(.*)\]$/, '$1');
      if (this.isValidIP(hostname)) return hostname;
    } catch {}
    return null;
  }

  /** True for loopback, private, link-local, CGNAT and other non-public addresses (IPv4 & IPv6) */
  static isPrivateIP(ipAddress: string): boolean {
    const ip = (ipAddress || '').trim().replace(/^\[(.*)\]$/, '$1');
    if (!this.isValidIP(ip)) return false;
    return isNonPublicIp(ip);
  }
}
