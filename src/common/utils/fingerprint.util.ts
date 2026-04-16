/**
 * @fileoverview Hardware and Browser Fingerprinting Engine for Zenith.
 * Provides immutable identity signatures for forensic tracking.
 * @packageDocumentation
 */

import * as crypto from 'crypto';
import { UAParser } from 'ua-parser-js';

/**
 * Represents the structure of an enterprise-grade device signature.
 */
export interface DeviceFingerprint {
  /** SHA-256 unique identifier for the hardware/browser combination */
  deviceId: string;
  /** Normalized operating system name and version */
  os: string;
  /** Normalized browser engine name and version */
  browser: string;
  /** Hardware category (e.g., mobile, desktop, tablet) */
  deviceType: string;
  /** Processor architecture (e.g., x64, arm64) */
  cpuArch: string;
  /** Flag identifying if the request originated from a known bot/crawler */
  isBot: boolean;
}

/**
 * FingerprintEngine class implements the logic for generating high-fidelity 
 * device signatures used in session protection and forensic auditing.
 * * @author Radouane Djoudi
 * @version 6.0.0
 */
export class FingerprintEngine {
  /**
   * Generates a unique SHA-256 device signature.
   * * @param userAgent - The raw User-Agent string from request headers.
   * @param ip - The client's IP address (IPv4 or IPv6).
   * @returns A detailed DeviceFingerprint object.
   * * @example
   * const fp = FingerprintEngine.generate(req.headers['user-agent'], req.ip);
   */
  static generate(userAgent: string, ip: string): DeviceFingerprint {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    const osName = result.os.name || 'UnknownOS';
    const browserName = result.browser.name || 'UnknownBrowser';
    const cpuArch = result.cpu.architecture || 'unknown';
    const deviceType = result.device.type || 'desktop';

    /**
     * Components are hashed to ensure privacy while maintaining unique identity.
     * We filter null/undefined to maintain hash consistency.
     */
    const components = [osName, result.os.version, browserName, cpuArch, deviceType, ip];
    const deviceId = crypto
      .createHash('sha256')
      .update(components.filter(Boolean).join('|'))
      .digest('hex');

    return {
      deviceId,
      os: `${osName} ${result.os.version || ''}`.trim(),
      browser: `${browserName} ${result.browser.version || ''}`.trim(),
      deviceType,
      cpuArch,
      isBot: /bot|googlebot|crawler|spider|robot|crawling/i.test(userAgent),
    };
  }
}