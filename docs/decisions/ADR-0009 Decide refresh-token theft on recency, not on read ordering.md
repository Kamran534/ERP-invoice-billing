---
tags: [adr]
status: accepted
date: 2026-07-31
deciders: [Muhammad Kamran]
---

# ADR-0009 — Decide refresh-token theft on recency, not on read ordering

**Status:** Accepted · **Supersedes:** — · **Related:** [[ADR-0002 Hybrid access and refresh tokens]]

## Context

Rotating refresh tokens make theft *detectable*: a token presented twice means two
parties hold it. The cost of getting the detection wrong is asymmetric and points
the wrong way — a missed theft leaves an attacker signed in, but a **false** theft
signal destroys a legitimate user's session, and false signals are far more common
than real ones. Four browser tabs whose access tokens expire together produce four
simultaneous refreshes of one token.

`RefreshTokenRepo.claim` read the row and then claimed it with a guarded
`UPDATE … WHERE used_at IS NULL`, and we treated that ordering as sufficient:

| what happened | verdict |
|---|---|
| read clean, guard updated 0 rows | concurrent — someone claimed it in between |
| read showed `used_at` already set | reuse — presumed theft |

The second row is wrong, and CI proved it. Ten parallel claims against real
Postgres returned one `ok`, some `concurrent`, and **four `reuse`** — because the
connection pool started those four *after* the winner had already committed. They
read a plainly-used row. So does a thief. There is no query that separates them:
by the time the loser looks, the only difference between "my sibling claimed this
1 ms ago" and "someone stole this last Tuesday" is *when*.

The integration test asserting `reuse` never occurs had passed for weeks on a
developer laptop, where the ten reads happened to be issued before the first write
landed. It was asserting a scheduling accident.

## Decision

The repository reports facts and stops classifying. `concurrent` remains a proof —
the guard failed after a clean read — but `reuse` means only "the row was already
spent when we looked", and it carries `usedAt`.

The use-case decides, on recency. A second presentation of a token claimed within
`tokens.refresh.inFlightWindowMs` (default 2 s) is a race and returns
`409 REFRESH_IN_PROGRESS`. Outside the window it is theft: the chain and the session
die, the user is emailed, and the caller gets a bare `401`.

This is a policy, and it lives with the other policy — `reuseGraceMs` — in
`packages/core`, not in SQL.

## Alternatives rejected

**Collapse the claim into a single atomic `UPDATE`.** One round trip fewer, and it
makes the token provably spendable once. But it discards the `concurrent` case
entirely: every loser then looks identical, so every multi-tab race becomes theft.
Strictly worse than what we had.

**Forgive on `replaced_by_id IS NULL` instead of on time.** Attractive because it is
a fact rather than a guess: the winner has claimed the row but not yet linked its
successor, so anything arriving in that gap is genuinely in flight. Rejected for two
reasons. The window is *too narrow* — the winner links its successor within
milliseconds, and a sibling arriving just after would be called theft — and it
fails open forever if the winner crashes between claim and link, leaving a token
that is permanently "in flight" and never trips detection.

**Raise `reuseGraceMs` instead of adding a knob.** It looks like the same idea, but
it forgives a different token: `reuseGraceMs` covers re-presenting the *predecessor*
of the current token, which is a client that fell behind. This covers re-presenting
*the same token* concurrently. Overloading one value would mean a deployment could
not have the safe default for one and a non-zero window for the other — and the
production audit warns about a non-zero `reuseGraceMs` precisely because it is the
riskier of the two.

**Accept the false positives.** Considered seriously, because forgiving anything at
all does widen the theft window. Rejected on the asymmetry: inside the window an
attacker receives a `409` and no tokens, so they gain a retry and nothing else,
while every attempt outside the window still trips full detection. A user who opens
a second tab, meanwhile, gets signed out.

## Consequences

A thief replaying within 2 seconds of the legitimate client is not detected on that
attempt. They obtain nothing from it, and their next attempt outside the window is
detected in full.

`inFlightWindowMs: 0` is now a supported way to be strict, and
`auditProductionConfig` flags it — the one configuration that reproduces the bug
this ADR fixes.

Tests that mean "this is theft" must now advance the clock past the window. The
`replay()` helper in `refresh.test.ts` exists to make that impossible to forget;
calling `rotate()` twice in a row now asserts the race rule, not the theft rule.

Reversing this means restoring a known false-positive.

## Related

[[AUTH-MODULE-PLAN#5.5.5 The concurrency false-positive (and why most implementations get logged out)]] ·
[[Auth module]] · [[Refresh token reuse detected]] · [[Testing]]
