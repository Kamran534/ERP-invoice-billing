---
tags: [moc, operations, runbooks]
updated: 2026-07-31
---

# Runbooks

What to do when an alert fires. Written before the incident, because nobody writes
a good runbook at 3am.

New one: `templates/Runbook`.

| Runbook | Trigger | Severity |
|---|---|---|
| [[Refresh token reuse detected]] | `auth_refresh_reuse_detected_total` > 0 | **Page** |
| [[OTP delivery outage]] | OTP delivery p95 > 30 s, or verify-failure ratio > 30% | High |
| [[User lost their 2FA device]] | Support request | Routine |
| [[Redis is down]] | Limiter backend unreachable | High |

## Not yet written

Placeholders from [[AUTH-MODULE-PLAN#16. Observability & operations]] — add them as
they become reachable:

- Mass credential stuffing
- Emergency signing-key rotation
- Trusted-device mass revocation
- Refresh-storm / client single-flight regression
- Rolling back an auth deploy (migrations must stay backward-compatible for one
  release so N-1 pods keep serving)

## Before you start any of these

- The `traceId` in an error body equals `x-request-id` and the `reqId` in the logs.
  Ask the reporter for it.
- `GET /health/ready` gives per-dependency status with latencies, and is cached for
  only 1 second.
- `docker compose logs api --tail 200` locally; your log aggregator in production.

## Related

[[Observability]] · [[Performance and scaling]] · [[Auth module]]
