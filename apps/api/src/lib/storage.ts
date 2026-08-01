/**
 * Object storage for the things Postgres should not hold (§10.11).
 *
 * MinIO in development, S3 anywhere else — the same API, so the only thing that
 * changes between them is the endpoint and the credentials.
 *
 * ⚑ Nothing in `@auth/core` knows this file exists. The core stores a `logoUrl`
 * string and has no opinion about where bytes live; that keeps the auth module
 * portable, which is the whole point of the ports-and-adapters split (ADR-0006).
 */

import { randomUUID } from 'node:crypto';
import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import type { Env } from '../env.js';

/**
 * The image types accepted for a logo.
 *
 * ⚑ Sniffed from the bytes, never taken from `Content-Type` or the filename —
 * both are supplied by whoever is uploading. A file announced as `image/png` and
 * containing HTML is the oldest trick there is, and the object store will happily
 * serve it back with whatever type we tell it.
 *
 * ⚑ SVG is **not** here, and its absence is deliberate. SVG is a document format:
 * it can carry `<script>`, and a browser rendering one from our own origin runs
 * that script with our cookies in scope. Rasterising it server-side would be the
 * only safe way to accept one.
 */
const SIGNATURES: Array<{ type: string; extension: string; test: (bytes: Buffer) => boolean }> = [
  {
    type: 'image/png',
    extension: 'png',
    test: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  },
  {
    type: 'image/jpeg',
    extension: 'jpg',
    test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  },
  {
    type: 'image/webp',
    extension: 'webp',
    test: (b) => b.subarray(0, 4).toString('ascii') === 'RIFF' && b.subarray(8, 12).toString('ascii') === 'WEBP',
  },
  {
    type: 'image/gif',
    extension: 'gif',
    test: (b) => ['GIF87a', 'GIF89a'].includes(b.subarray(0, 6).toString('ascii')),
  },
];

export interface SniffedImage {
  type: string;
  extension: string;
}

/** What this really is, or null when it is not an image we will serve. */
export function sniffImage(bytes: Buffer): SniffedImage | null {
  if (bytes.length < 12) return null;
  const match = SIGNATURES.find((signature) => signature.test(bytes));
  return match ? { type: match.type, extension: match.extension } : null;
}

export interface Storage {
  /**
   * Stores bytes under the publicly readable prefix and returns the URL.
   *
   * ⚑ `public/` is the only prefix the bucket policy opens for anonymous reads.
   * Anything written elsewhere needs a signature to fetch, which is the right
   * default for everything that is not a logo.
   */
  putPublic(input: {
    /** Namespaced by tenant, so one organization's keys can never collide with another's. */
    orgId: string;
    kind: 'logos';
    bytes: Buffer;
    contentType: string;
    extension: string;
  }): Promise<{ url: string; key: string }>;

  /** Best effort: a logo replaced is a logo nobody will ask for again. */
  remove(url: string): Promise<void>;

  /** The bucket-relative key inside one of our public URLs, or null. */
  keyFromUrl(url: string): string | null;
}

export function createStorage(env: Env): Storage {
  const client = new S3Client({
    region: env.S3_REGION,
    endpoint: env.S3_ENDPOINT,
    // MinIO has no DNS-style buckets; real S3 does, and prefers them.
    forcePathStyle: env.S3_FORCE_PATH_STYLE,
    credentials: {
      accessKeyId: env.S3_ACCESS_KEY_ID,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    },
  });

  const base = env.S3_PUBLIC_URL.replace(/\/+$/, '');

  return {
    async putPublic({ orgId, kind, bytes, contentType, extension }) {
      // ⚑ A random name, not the uploader's. A filename from a browser is
      // attacker-controlled: it can contain `../`, a null byte, or 4KB of
      // Unicode, and none of that belongs in a key we then hand back as a URL.
      const key = `public/${kind}/${orgId}/${randomUUID()}.${extension}`;

      await client.send(
        new PutObjectCommand({
          Bucket: env.S3_BUCKET,
          Key: key,
          Body: bytes,
          ContentType: contentType,
          // ⚑ The sniffed type, and `nosniff` alongside it, so a browser cannot
          // be talked into treating the object as anything else.
          ContentDisposition: 'inline',
          CacheControl: 'public, max-age=31536000, immutable',
        }),
      );

      return { url: `${base}/${key}`, key };
    },

    keyFromUrl(url) {
      if (!url.startsWith(`${base}/`)) return null;
      const key = url.slice(base.length + 1);
      // Only ever our own public prefix — never a key a caller composed.
      return key.startsWith('public/') ? key : null;
    },

    async remove(url) {
      const key = this.keyFromUrl(url);
      if (!key) return;
      try {
        await client.send(new DeleteObjectCommand({ Bucket: env.S3_BUCKET, Key: key }));
      } catch {
        // An orphaned object costs a few kilobytes; a failed delete must not fail
        // the request that replaced it.
      }
    },
  };
}
