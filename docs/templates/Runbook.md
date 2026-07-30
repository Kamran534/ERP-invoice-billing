---
tags: [runbook]
severity: 
alert: 
updated: {{date:YYYY-MM-DD}}
---

# {{title}}

**Alert:** `metric_or_condition`
**Spec:** 

One line: what is actually wrong, and whether it is urgent.

## What already happened automatically

What the system has already done before a human was involved. Knowing the blast
radius is contained changes how fast you have to move.

## Triage

Ordered from most to least likely cause. Include the query or command for each —
a runbook that says "check the logs" is not a runbook.

## Fix

Numbered steps. Note anything irreversible **before** the step, not after.

## Do not

The tempting wrong fixes, and why they are wrong. This section is why the runbook
exists at 3am.

## After

Follow-up, and what would stop it recurring.

## Related
