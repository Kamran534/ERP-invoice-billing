/**
 * What the upload endpoint will and will not accept (§10.11).
 *
 * This is the security boundary of the only route that takes bytes, so the tests
 * that matter are the refusals — and in particular the ones where the *caller*
 * has said something contradicted by the file itself.
 */

import { describe, it, expect } from 'vitest';
import { sniffImage } from './storage.js';

const png = () =>
  Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(32),
  ]);
const jpeg = () => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(32)]);
const webp = () =>
  Buffer.concat([
    Buffer.from('RIFF', 'ascii'),
    Buffer.from([0, 0, 0, 0]),
    Buffer.from('WEBP', 'ascii'),
    Buffer.alloc(32),
  ]);
const gif = () => Buffer.concat([Buffer.from('GIF89a', 'ascii'), Buffer.alloc(32)]);

describe('sniffImage', () => {
  it('recognises the formats a logo may be', () => {
    expect(sniffImage(png())).toEqual({ type: 'image/png', extension: 'png' });
    expect(sniffImage(jpeg())).toEqual({ type: 'image/jpeg', extension: 'jpg' });
    expect(sniffImage(webp())).toEqual({ type: 'image/webp', extension: 'webp' });
    expect(sniffImage(gif())).toEqual({ type: 'image/gif', extension: 'gif' });
  });

  it('⚑ refuses SVG, whatever it calls itself', () => {
    // SVG is a *document* format: it can carry <script>, and a browser rendering
    // one served from our own origin runs that script with our cookies in scope.
    // Accepting it would turn "upload your logo" into stored XSS.
    const svg = Buffer.from(
      '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
      'utf8',
    );
    expect(sniffImage(svg)).toBeNull();
  });

  it('⚑ refuses HTML dressed as an image', () => {
    const html = Buffer.from('<!doctype html><html><body>hello</body></html>', 'utf8');
    expect(sniffImage(html)).toBeNull();
  });

  it('⚑ refuses a file whose extension and bytes disagree', () => {
    // `logo.png` containing a zip. The name and the declared content type are the
    // caller's to choose; only the bytes are not.
    const zip = Buffer.concat([Buffer.from('PK', 'ascii'), Buffer.alloc(32)]);
    expect(sniffImage(zip)).toBeNull();
  });

  it('refuses something too short to identify', () => {
    expect(sniffImage(Buffer.from([0x89, 0x50]))).toBeNull();
    expect(sniffImage(Buffer.alloc(0))).toBeNull();
  });

  it('⚑ does not mistake a RIFF container for WebP', () => {
    // A .wav is RIFF too. Checking only the first four bytes would accept audio
    // and then serve it with `Content-Type: image/webp`.
    const wav = Buffer.concat([
      Buffer.from('RIFF', 'ascii'),
      Buffer.from([0, 0, 0, 0]),
      Buffer.from('WAVE', 'ascii'),
      Buffer.alloc(32),
    ]);
    expect(sniffImage(wav)).toBeNull();
  });
});
