---
tags: [runbook, security, auth]
severity: page
alert: auth_refresh_reuse_detected_total
updated: 2026-07-31
---

# Refresh token reuse detected

> [!danger] This is the one alert that pages a human
> A refresh token was presented twice. Two parties hold the same credential. The
> system has already contained it — your job is to work out *how* it happened.

**Alert:** `increase(auth_refresh_reuse_detected_total[5m]) > 0`
**Spec:** [[AUTH-MODULE-PLAN#5.5.4 Reuse means presumed theft]]

## What already happened automatically

Before you were paged, the system:

1. revoked the **entire token chain** for that session,
2. revoked the session (`revoked_reason = 'reuse_detected'`),
3. wrote a high-severity audit row and emitted `security.refresh_reuse_detected`,
4. emailed the user "we signed you out of a device",
5. returned a bare `401` to the caller — deliberately never explaining why.

So the compromised session is already dead. Nothing you do needs to be fast.

## Triage: theft, or a broken client?

Most reuse alerts are **not** theft. Work through this order.

### 1. Is it a client-side single-flight regression?

By far the most likely cause. Check `auth_refresh_concurrent_total` over the same
window:

- **Climbing alongside the reuse alarm** → a client is refreshing in parallel from
  several tabs. Its single-flight coalescing has regressed. Not an attack.
  → Find the client release that changed, fix it (see
  [[AUTH-MODULE-PLAN#13.3 Single-flight refresh (mandatory, not an optimization)]]),
  and note the affected users will have seen a spurious logout.

- **Flat** → keep going.

### 2. How many users?

```sql
SELECT actor_user_id, count(*), min(occurred_at), max(occurred_at)
FROM auth_audit_events
WHERE event = 'auth.refresh_reuse_detected'
  AND occurred_at > now() - interval '24 hours'
GROUP BY actor_user_id ORDER BY 2 DESC;
```

- **One user, once** → most likely a flaky network plus an aggressive client
  retry. Confirm with the user; watch.
- **One user, repeatedly** → treat as a compromised device for that user.
- **Many users** → escalate. This is either a client bug shipped to everyone, or a
  token leak (a logging change, a proxy caching a response, an XSS).

### 3. Where did the two presentations come from?

```sql
SELECT occurred_at, ip, user_agent, metadata
FROM auth_audit_events
WHERE event LIKE 'auth.refresh%' AND actor_user_id = $1
ORDER BY occurred_at DESC LIMIT 50;
```

Two different IPs or user-agents seconds apart is the theft signature. The same
client retrying is not.

## If it is theft

1. **Revoke everything for that user**, not just the session:
   `auth sessions revoke --user <id>` and `auth devices revoke --user <id>`.
2. Force a password reset, and check whether MFA was enrolled at the time.
3. Work out the exfiltration route. A refresh token only leaves the browser through
   a small number of doors:
   - **Logging** — did a recent change log a request body or `set-cookie`? The
     redaction list is in `apps/api/src/app.ts`; anything not on it is at risk.
   - **Caching** — did a proxy or CDN cache an `/auth` response? Every one carries
     `no-store`; verify that survived the edge.
   - **XSS in the client** — cookie mode makes the token unreadable from JS, so
     this implies bearer mode or a cookie misconfiguration.
   - **Device compromise** — nothing server-side will have caught it.
4. Consider `reuseRevokesAllSessions: true` temporarily, which kills every session
   for the user on any reuse rather than just the compromised one.

## If the alert is noisy and none of it is theft

Do **not** raise the threshold. The options, in order of preference:

1. Fix the client's single-flight. This is almost always the right answer.
2. Set `tokens.refresh.reuseGraceMs` to a small non-zero value (max 10 s), which
   lets the *immediate predecessor* be re-presented once without alarming.
   ⚑ This widens the theft window and is off by default for that reason. Record the
   decision if you turn it on.

## Prevention

- The `409 REFRESH_IN_PROGRESS` path exists so a genuine race does not look like
  theft. If clients are seeing 401 rather than 409, the guard row may not be doing
  its job — check the transaction isolation in the refresh use-case.
- [[Testing]] has a 22-case refresh matrix including 4-concurrent-refresh with zero
  false alarms. If you change rotation, run it.

## Related

[[ADR-0002 Hybrid access and refresh tokens]] · [[Observability]] · [[Auth module]]
