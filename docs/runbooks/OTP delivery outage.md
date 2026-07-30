---
tags: [runbook, operations, auth]
severity: high
alert: auth_otp_delivery_duration_seconds
updated: 2026-07-31
---

# OTP delivery outage

**Alerts:** OTP delivery p95 > 30 s · OTP verify-failure ratio > 30% for 10 min
**Spec:** [[AUTH-MODULE-PLAN#5.11 Login by one-time passcode (OTP)]]

This is a **conversion incident as much as a security one**. Users abandon a sign-in
at around 30 seconds, so slow delivery loses customers as surely as a hard failure.

## Is it delivery, or is it an attack?

A verify-failure spike has two very different causes:

| Signal | Reading |
|---|---|
| `auth_otp_total{result="failed"}` up **and** delivery p95 up | Delivery is slow; users are typing stale or superseded codes |
| Failures up, delivery **normal** | Guessing campaign. Check source IP spread and `otp_challenge_exhausted` |
| `auth_otp_total{result="delivery_failed"}` up | The provider is refusing or timing out |

Remember only one challenge is live per destination: if a user requests twice, the
first code stops working. Slow delivery makes that routine, and it looks exactly
like users entering wrong codes.

## Decision tree

1. **Check the mailer directly.** `GET /health/ready` reports `smtp` with a latency.
   It is a *soft* dependency, so the service still reports `ready` — read the
   `checks.smtp` field, not the top-level status.
2. **Provider degraded but reachable** → wait it out if p95 is under ~60 s and
   falling. Post a status note; codes are still arriving.
3. **Provider down** → fail over to the secondary relay by changing `SMTP_*` and
   restarting. Mail is queued and retried, and `send()` never throws into a login,
   so authentication itself keeps working — only OTP and password reset are
   affected.
4. **No secondary available** → tell users to sign in with a password. OTP is a
   convenience factor; password + 2FA is unaffected by a mail outage.

> [!danger] Do not extend the OTP TTL
> It is the tempting fix and it is wrong. Six digits is ~20 bits, safe **only**
> because three limits hold simultaneously: a 5-attempt cap, one live challenge per
> destination, and a 10-minute expiry. Lengthening the window weakens the factor for
> everyone, permanently, to work around a temporary provider problem.

## Do not

- Raise `maxAttempts` to reduce support load.
- Disable `bindToClient`. It is what stops "an attacker phones you and asks you to
  read out the code".
- Turn on `allowSignup` to let stuck users through.

## After

- Was the bounce/complaint feedback loop honoured? A suppressed address silently
  never receives codes.
- Check `otp_challenge_exhausted` for users who burned all 5 attempts on stale
  codes — they may need a support touch.
- If this recurs, the fix is a second provider, not looser limits.

## Related

[[Observability]] · [[Docker stack#Mailpit]] · [[Auth module]]
