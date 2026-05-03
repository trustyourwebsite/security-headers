import { describe, it, expect } from 'vitest';
import { detectWaf } from '../src/waf-detector.js';

describe('detectWaf', () => {
  it('returns blocked=false for status 200 with no WAF headers', () => {
    expect(detectWaf(200, { server: 'nginx' })).toEqual({
      blocked: false,
      vendor: null,
    });
  });

  it('returns blocked=false for status 200 even when fronted by Cloudflare', () => {
    expect(
      detectWaf(200, { server: 'cloudflare', 'cf-ray': '8f1e2a3b4c5d6e7f-AMS' })
    ).toEqual({ blocked: false, vendor: null });
  });

  it('detects Akamai via x-blocked-by-waf header', () => {
    expect(
      detectWaf(403, {
        server: 'AkamaiGHost',
        'x-blocked-by-waf': 'true',
      })
    ).toEqual({ blocked: true, vendor: 'Akamai' });
  });

  it('detects Akamai via server header alone', () => {
    expect(detectWaf(403, { server: 'AkamaiGHost' })).toEqual({
      blocked: true,
      vendor: 'Akamai',
    });
  });

  it('detects Cloudflare via cf-mitigated header', () => {
    expect(
      detectWaf(403, { server: 'cloudflare', 'cf-mitigated': 'challenge' })
    ).toEqual({ blocked: true, vendor: 'Cloudflare' });
  });

  it('detects Cloudflare via cf-ray on a 403', () => {
    expect(detectWaf(403, { 'cf-ray': '8f1e2a3b4c5d6e7f-AMS' })).toEqual({
      blocked: true,
      vendor: 'Cloudflare',
    });
  });

  it('detects AWS WAF via x-amzn-waf-action', () => {
    expect(detectWaf(403, { 'x-amzn-waf-action': 'block' })).toEqual({
      blocked: true,
      vendor: 'AWS WAF',
    });
  });

  it('detects Sucuri via x-sucuri-id', () => {
    expect(detectWaf(403, { 'x-sucuri-id': '12345' })).toEqual({
      blocked: true,
      vendor: 'Sucuri',
    });
  });

  it('detects Imperva/Incapsula via x-iinfo', () => {
    expect(detectWaf(403, { 'x-iinfo': '0-12345-67890 NNNN CT(0 0 0)' })).toEqual({
      blocked: true,
      vendor: 'Imperva',
    });
  });

  it('detects Fastly block via x-cdn header', () => {
    expect(detectWaf(429, { 'x-cdn': 'Fastly' })).toEqual({
      blocked: true,
      vendor: 'Fastly',
    });
  });

  it('returns blocked=true with null vendor for generic 429', () => {
    expect(detectWaf(429, { server: 'nginx' })).toEqual({
      blocked: true,
      vendor: null,
    });
  });

  it('returns blocked=true with null vendor for plain 403', () => {
    expect(detectWaf(403, { server: 'nginx' })).toEqual({
      blocked: true,
      vendor: null,
    });
  });

  it('returns blocked=false for 404 even with WAF-like headers (status not in block range)', () => {
    expect(detectWaf(404, { 'x-blocked-by-waf': 'true' })).toEqual({
      blocked: false,
      vendor: null,
    });
  });

  it('returns blocked=false for 500 server error without WAF signature', () => {
    expect(detectWaf(500, { server: 'nginx' })).toEqual({
      blocked: false,
      vendor: null,
    });
  });
});
