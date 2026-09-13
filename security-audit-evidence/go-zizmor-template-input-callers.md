# Go workflow template-input caller review

Checked against audited commit `71a73228cd2bc001cdc5d485a16621a24bfae15a` on 2026-09-13. This is a call-site review of the 35 `template-injection/High` entries in the local zizmor v1.30.1 offline JSON output, not an online GitHub runner test.

| Composite action | Flags | Inputs expanded into shell | Reviewed callers |
| --- | ---: | --- | --- |
| `archive-plugins` | 12 | `tag` (3), `os` (4), `arch` (4), `source-dir` (1) | `release.yml` passes a `git describe` tag and fixed OS/architecture matrix entries plus literal `plugins_dist`. The tag is externally variable on a tag push. |
| `build` | 8 | `app-name` (1), `os` (2), `arch` (1), `embedca` (2), `tag` (2) | `release.yml` passes a `git describe` tag and fixed matrix/env values. `main.yml` omits `tag` and uses fixed matrix/env values. The action later passes the tag-containing output into another `run:` command. |
| `build-aar` | 3 | `version` (2), `android-api` (1) | `release.yml` passes a `git describe` tag as `version`; `main.yml` omits it. Both use the action's literal default `android-api: '26'`. |
| `e2e` | 5 | `app-name`, `os`, `arch` | Only `main.yml` calls it, with fixed env/matrix values. |
| `e2e-realnet` | 7 | `pair`, `app-name`, `os`, `arch` | Only `main.yml` calls it, with fixed env/matrix values. |

**Seven flagged expansions** directly use the externally variable release tag in the reviewed workflow; the other 28 flags use caller-controlled action inputs that the checked workflows currently supply as fixed values or enumerated matrices. The latter remain dangerous *interfaces* if a later workflow passes untrusted data. The tag-controlled output in `build` creates an additional downstream shell path beyond the scanner's seven direct flags. The release workflow triggers on every pushed tag (`tags: ['*']`) and has write-capable release jobs. The local command-substitution reproduction is in `go-release-tag-injection.json`; no malicious tag was pushed to GitHub and no remote exploit was observed.
