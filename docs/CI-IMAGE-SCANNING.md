# Image vulnerability scanning — brief for the application team

This is a hand-over document. It asks the team that owns an application repository to scan its own
container images in CI, and explains why that work moved there rather than staying on the fleet.

## Why this belongs in your repository, not in the fleet auditor

The control plane can scan the images running on a host, and for a while it did. It was the wrong
place, for one reason: **the fix does not live there.** A vulnerable package in a base image is
fixed by changing a tag or a lockfile in your repository and rebuilding. The fleet auditor can only
observe the result, weeks later, after it is already serving traffic. Alerting somebody who cannot
act is how an alert stream gets ignored.

Scanning in CI inverts that. The finding arrives with the change that caused it, in front of the
person who can fix it, before it reaches production.

**What the fleet still does, so you do not build it twice:** it checks that what is *running* is
what you think you shipped — image age and drift between the deployed container and the tag. That
is a different question from "is this image vulnerable", and CI cannot answer it, because CI only
ever sees the image it just built. If a deploy silently failed six weeks ago, only the host knows.

## What your first scan will find

Measured on `segcore-demo` on 2026-09-07, so this is not a guess:

| Image | Fixable | Total |
|---|---|---|
| `segcore-site` | 37 | 37 |
| `gimsv2-backend` | 14 | 14 |
| `gimsv2-company-simulator` | 14 | 14 |
| `gimsv2-frontend` / `admin-frontend` / `portal-frontend` | 9 each | 9 each |

**Every single finding has a published fix.** Nothing here is an unfixable distro CVE you would
have to live with, which means a policy of "fail on fixable" is entirely actionable from day one.

They fall into two groups, and the two are fixed differently:

- **Base image OS packages** — `tar`, `libuuid`, `libcrypto3`, `libssl3`. These come from the
  Alpine/Debian layer, not from your code. They are fixed by **rebuilding against a current base
  image**, not by changing anything you wrote. A pinned base tag stops receiving them the day it is
  pinned, which is why the scheduled rebuild below matters as much as the scan.
- **npm dependencies** — `next`, `brace-expansion`, `minimatch`, `ip-address`. Fixed by updating
  the lockfile.

## What to implement

### 1. Scan the built image, on every pull request

Trivy, against the image you just built — not against the Dockerfile, and not against the source
tree alone. The image is what ships.

```yaml
# .github/workflows/image-scan.yml
name: image scan
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 4 * * 1'        # see §3: this is not optional decoration

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false          # one bad image must not hide the others
      matrix:
        image: [backend, frontend, admin-frontend, portal-frontend, company-simulator]
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: docker build -t scan-target:${{ matrix.image }} -f ${{ matrix.image }}/Dockerfile .

      # Cache the vulnerability DB: without this every job re-downloads ~120 MB, and a rate limit
      # from ghcr turns into a red build that has nothing to do with your code.
      - uses: actions/cache@v4
        with:
          path: ~/.cache/trivy
          key: trivy-db-${{ github.run_id }}
          restore-keys: trivy-db-

      - name: Scan (fail on fixable CRITICAL/HIGH)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: scan-target:${{ matrix.image }}
          scanners: vuln          # not secret/misconfig — different problem, different noise
          severity: CRITICAL,HIGH
          ignore-unfixed: true    # THE important flag; see below
          exit-code: '1'
          cache-dir: ~/.cache/trivy
```

### 2. `--ignore-unfixed` is the flag that decides whether this survives

Without it the build fails on vulnerabilities upstream has no fix for. There is nothing to do about
those, so the failure is noise, and within two weeks somebody adds `continue-on-error` and the
whole thing becomes decoration. With it, every failure is a real task with a known remedy.

This is not a hypothetical: the fleet auditor's first run produced 40 simultaneous alerts because
it alerted on every image with any finding. The rule had to be rewritten. Learn from that here
rather than repeating it.

If 37 findings on day one is too much to clear at once, **do not lower the severity — raise the
bar over time**: start with `severity: CRITICAL` and `exit-code: 1`, report HIGH without failing,
and move HIGH to blocking once the backlog is down. A budget that ratchets is honest; a permanently
red pipeline is not.

### 3. The scheduled rebuild matters as much as the scan

Most of your findings are OS packages in the base layer. They appear because the base image was
patched upstream after you last built. A scan on pull requests only runs when someone changes code,
so a repository with no commits for a month is a repository whose images silently rot.

The weekly `schedule:` trigger above rebuilds and rescans with no code change. It is what turns
"we scan" into "we are current".

### 4. Keep the base images moving

Scanning tells you; it does not fix. Enable **Dependabot** or **Renovate** for both the Dockerfile
base images and the npm lockfiles. That is what actually closes the findings; the scan is the check
that it worked.

Note the tension with pinning: `postgres:18.6-alpine` is a good pin because it is reproducible, but
a pin stops receiving patches by definition. Pin *and* let an automated PR move the pin. Pinning
without that is how an image ends up two years old.

### 5. Publish an SBOM with each build (optional, cheap)

```bash
trivy image --format cyclonedx --output sbom.json scan-target:backend
```

Attach it to the build artefacts. The next time a CVE lands in the news, "are we affected?" becomes
a grep instead of an afternoon.

## Two practical traps

- **Java archives.** If any image contains a `.jar`, trivy insists on its Java index database — a
  ~1 GB download — and **fails the whole scan** rather than degrading if it cannot get it. In CI
  with a warm cache this is fine; just do not add `--skip-java-db-update` to "speed it up", because
  the failure mode is a hard error, not a smaller report. We hit exactly this on the fleet.
- **Locally built images have no registry.** Your images are built on the host at deploy time, so
  there is no registry copy for anything to scan later. CI must build them itself, the same way, or
  it is scanning something that never ships.

## What to send back

Once this is running, the fleet auditor stops alerting on image CVEs entirely. What would be useful
in return:

1. Confirmation of the policy you settled on (which severities block, which only report), so the
   fleet's expectations match yours.
2. Whether the weekly rebuild is enabled — that is the part that decays quietly if it is not.
