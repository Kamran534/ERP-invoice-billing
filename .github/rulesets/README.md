# Branch rulesets

**These files are not applied automatically.** Unlike `dependabot.yml`, GitHub does
not read rulesets from the repository — they live in repository settings. These are
committed so the intended protection is reviewable, versioned, and importable in two
clicks rather than retyped into a form.

## Import

Repository → **Settings** → **Rules** → **Rulesets** → **New ruleset** →
**Import a ruleset** → choose the file → **Create**.

## Which one

| File | Blocks | Leaves working |
|---|---|---|
| `main-baseline.json` | force-push, branch deletion | pushing straight to `main` |
| `main-full.json` | the above, plus merging without a PR or with red CI | only merges through a PR |

**Start with `main-baseline.json`.** It is pure safety net — it prevents the two
things that lose history, and costs nothing while one person is pushing directly to
`main`.

> [!warning] `main-full.json` changes how you work
> Requiring status checks blocks direct pushes to `main`, because the checks cannot
> have passed for a commit that does not exist upstream yet. Every change then goes
> via a branch and a pull request. That is the right end state, and the wrong thing
> to switch on the day before you need to push a fix.
>
> `required_approving_review_count` is `0` on purpose: GitHub does not let you
> approve your own pull request, so `1` would deadlock a solo repository.

## The contexts must match the job names

`main-full.json` names three required checks:

```
Build, typecheck, unit tests
Integration, e2e and coverage
Docker image
```

These are the `name:` values of the jobs in `../workflows/ci.yml`, which is what
GitHub reports as the check name. **Renaming a job silently breaks this**, in the
worse of the two possible directions: the ruleset waits forever for a check that no
longer reports, and `main` becomes unmergeable. If you rename a job, re-import the
ruleset.

## Related

`docs/Git and CI.md`
