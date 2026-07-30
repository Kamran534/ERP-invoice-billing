---
tags: [runbook, support, auth]
severity: routine
updated: 2026-07-31
---

# User lost their 2FA device

**Spec:** [[AUTH-MODULE-PLAN#5.4.4 Recovery]]

The account is not lost. The order below goes from least to most privileged — stop
as soon as one works.

## 1. Recovery codes

Ten single-use codes were shown once at enrolment. Ask the user to try one at the
2FA prompt. Using one emails them and prompts regeneration.

Check how many remain before assuming they have none:

```sql
SELECT count(*) FILTER (WHERE used_at IS NULL) AS remaining
FROM auth_recovery_codes WHERE user_id = $1;
```

## 2. Another enrolled factor

A passkey or a second authenticator often exists and has been forgotten:

```sql
SELECT type, label, confirmed_at, last_used_at
FROM auth_mfa_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL;
```

## 3. A trusted device

If trusted devices are enabled and the user still has a browser that was remembered,
signing in there skips 2FA. ⚑ It will **not** let them change credentials — trust is
never accepted for step-up — but it gets them working while you sort out enrolment.

## 4. Admin factor reset — the human step

> [!warning] This is the weakest link in the whole system
> Every technical control above can be bypassed by a support agent who resets a
> factor for the wrong person. Social engineering targets this step, not the
> cryptography. Identity proof is the control.

**Required before reset** — follow your organisation's policy; at minimum:

- verify identity out-of-band, not through the channel that made the request;
- confirm details an attacker is unlikely to hold (recent invoice numbers, billing
  contact, org details);
- for **owner or admin** roles, require a second approver.

Then:

```bash
auth user reset-mfa --user <id>
```

This audits (`mfa.factor_removed`, actor = you), emails the user, and revokes all
trusted devices. The account drops into the enrolment quarantine: it can reach only
`/auth/me` and the enrolment endpoints until a new factor is confirmed.

## Never

- Disable MFA enforcement for the org to unblock one user.
- Read a code to the user, or accept one they read to you.
- Use security questions as identity proof. They are guessable and NIST deprecates
  them.

## After

Confirm re-enrolment completed and new recovery codes were issued — a user stuck in
quarantine will just call back.

## Related

[[Auth module]] · [[AUTH-MODULE-PLAN#5.4.6 Enforcement policy and the enrollment quarantine]]
