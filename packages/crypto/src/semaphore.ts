/**
 * Bounded-concurrency gate with a queue timeout.
 *
 * Why this exists: Argon2id is *memory*-hard by design. At 19 MiB per hash, 200
 * concurrent logins is ~3.8 GiB of transient RSS — the process OOMs long before
 * the CPU saturates. A login flood is therefore a trivial memory-exhaustion DoS
 * unless hashing concurrency is capped.
 *
 * With a cap, excess requests queue briefly and then shed with 503 (which the
 * load balancer can retry elsewhere) instead of killing the container.
 */

export class QueueTimeoutError extends Error {
  constructor(waitedMs: number) {
    super(`Timed out after ${waitedMs}ms waiting for a slot`);
    this.name = 'QueueTimeoutError';
  }
}

interface Waiter {
  resolve: () => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

export class Semaphore {
  #available: number;
  readonly #queue: Waiter[] = [];
  readonly #timeoutMs: number;

  #peakQueueDepth = 0;
  #totalShed = 0;

  constructor(permits: number, timeoutMs: number) {
    if (permits < 1) throw new Error('Semaphore needs at least 1 permit');
    this.#available = permits;
    this.#timeoutMs = timeoutMs;
  }

  get queueDepth(): number {
    return this.#queue.length;
  }
  get available(): number {
    return this.#available;
  }
  /** Exported as a gauge so the cap can be tuned from real data, not guesses. */
  get stats(): { queueDepth: number; peakQueueDepth: number; shed: number } {
    return { queueDepth: this.#queue.length, peakQueueDepth: this.#peakQueueDepth, shed: this.#totalShed };
  }

  async acquire(): Promise<void> {
    if (this.#available > 0) {
      this.#available -= 1;
      return;
    }
    return new Promise<void>((resolve, reject) => {
      const waiter: Waiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const idx = this.#queue.indexOf(waiter);
          if (idx !== -1) this.#queue.splice(idx, 1);
          this.#totalShed += 1;
          reject(new QueueTimeoutError(this.#timeoutMs));
        }, this.#timeoutMs),
      };
      // Do not keep the event loop alive purely for a queued waiter.
      waiter.timer.unref?.();
      this.#queue.push(waiter);
      if (this.#queue.length > this.#peakQueueDepth) this.#peakQueueDepth = this.#queue.length;
    });
  }

  release(): void {
    const next = this.#queue.shift();
    if (next) {
      clearTimeout(next.timer);
      next.resolve();
      return;
    }
    this.#available += 1;
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}
