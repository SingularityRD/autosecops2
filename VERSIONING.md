# Versioning

Vigil uses semantic versioning. This file says what a caller may rely on across
releases and how that changes. How `VERSION` itself is bumped is on the
[releasing page](https://vigilsoc.org/docs/releasing/).

## What is frozen

- **The `/api/v1` HTTP contract.** Every path, operation and shape in
  [`core/api/v1/contract.snapshot.json`](core/api/v1/contract.snapshot.json).
  Routes marked `x-vigil-beta` are served under `/api/v1` but are versioned,
  not frozen: they are left out of the snapshot and may change until their
  shape settles.
- **The frozen tools on the `vigil` MCP server** at `/mcp`. The name and input
  schema of every tool in `FROZEN_TOOLS` (`tools/mcp/vigil.py`), as held by
  [`tools/mcp/frozen_tools.snapshot.json`](tools/mcp/frozen_tools.snapshot.json).
  Tools the server serves outside that set carry the `0.x` terms: they may
  change in any minor.

## What is not frozen

- Every `/api/*` route without a version: the console's own wiring. That
  includes analytics and reporting, `/api/config`, `/api/orchestrator`,
  `/api/llm/providers`, `/api/services` and `/api/ai`.
- `/internal/*`.
- The web console (`clients/web/`).
- The `WORKFLOW.md`, `SKILL.md` and `INTENT.md` file formats.

## How a frozen surface changes

- **Within a major, only additively.** New routes, new optional fields, new
  tools in the frozen set.
- **Removal or an incompatible shape change is a major.**
- **The legacy aliases.** Contract routers are also mounted at their old
  `/api/<resource>` paths through `RouterMeta.legacy_prefixes` (see
  [How dual-mounting works](core/api/v1/README.md#how-dual-mounting-works)).
  They are deprecated once the console has moved to `/api/v1`, and removed no
  earlier than 2.0.
- **Movement is one way.** A surface may move from unfrozen to frozen; nothing
  moves out of the open product.

## Changing the contract on purpose

Both snapshots are enforced by a drift test that fails on any difference. To
change one deliberately, run its generator, commit the snapshot diff, and say
so in the PR:

- `/api/v1`: see [Enforcement](core/api/v1/README.md#enforcement-the-contract-snapshot)
  (`scripts/generate_api_v1_contract.py`).
- MCP: `scripts/generate_mcp_frozen_tools.py`, checked by
  `tests/unit/api/test_mcp_frozen_tools.py`.

## AutoSecOps 2.0

AutoSecOps 2.0.0 is a major because the release artifacts moved
(`ghcr.io/singularityrd/autosecops-*` instead of `ghcr.io/vigil-soc/vigil-*`) and
the product name changed. The frozen surfaces above are unchanged: no `/api/v1`
operation and no frozen MCP tool was removed or changed incompatibly. The
legacy `/api/<resource>` aliases are still mounted in 2.0.0; removing them is a
later major.

## Release tags

The release workflow (`.github/workflows/release.yml`) runs on any `v*` tag in
SingularityRD/autosecops2 and refuses tags other than `v<VERSION>` and
`v<VERSION>-rc.<N>`, where `<VERSION>` is the content of the `VERSION` file.
release-please is not active in this repository, so the steps are manual:

1. **Prepare on `integration`.** Bump `VERSION` and every file
   `.github/release-please-config.json` lists under `extra-files` (plus
   `.github/.release-please-manifest.json`); keep the WP table
   `docs/release/<VERSION>.json` current and render the release notes
   `docs/release/<VERSION>.md` and the generated `CHANGELOG.md` block with
   `release_tool.py render-notes --data docs/release/<VERSION>.json --write`.
   `python3 scripts/release/release_tool.py check-versions` must pass.
2. **Rehearse offline.** `scripts/release/dry-run.sh --out /tmp/rel --strict-notes`
   checks versions, checks that every work package marked "Dahil" was merged,
   that every merged `wp/<id>-*` branch has a "Dahil" row and that the notes
   are freshly rendered, and builds and checksums the lockfile
   SBOMs. The tag pipeline runs the same checks and fails before building
   anything if they do not pass.
3. **Release candidate.** Merge `integration` into `main`, then tag the merge
   commit `v<VERSION>-rc.<N>` (annotated and signed: `git tag -s`). The
   workflow publishes images tagged `<VERSION>-rc.<N>` (no `latest`, no
   `<major>.<minor>`) and a draft prerelease.
4. **GA.** Only after the GA decision (for 2.0.0: the meeting of 30 October
   2026) a release manager tags the same commit `v<VERSION>`. The workflow
   publishes `<VERSION>`, `<major>.<minor>` and `latest`, signs everything and
   creates a **draft** GitHub Release; the release manager reviews it and
   publishes it.
5. **Desktop installers.** The `desktop` jobs build the macOS dmg (arm64, x64),
   the Linux AppImage and the Windows NSIS installer. OS code signing needs
   repository secrets that a person provides; without them the installers are
   built anyway, named `*-unsigned.*`, and covered only by the cosign
   signature and `SHA256SUMS` like every other release file:
   - macOS (Developer ID + notarization): `CSC_LINK` (base64 of the
     "Developer ID Application" `.p12`), `CSC_KEY_PASSWORD`, `APPLE_ID`,
     `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`. A certificate without the
     three notarization secrets fails the job.
   - Windows (Authenticode): `WIN_CSC_LINK` (base64 of the `.pfx`),
     `WIN_CSC_KEY_PASSWORD`.
6. **Never move or delete a pushed release tag.** A wrong release is fixed by a
   new patch version. Signatures stay in the public Sigstore log either way.

The tag pipeline also refuses a tag whose commit is not an ancestor of `main`
(the `version` job fetches `main` and runs `release_tool.py check-on-main`), and
refuses release notes that are not exactly what
`release_tool.py render-notes --data docs/release/<VERSION>.json` produces from
the tagged commit's merge history: regenerate them on `main` right before
tagging (`render-notes ... --write`, commit, merge).

## Tag protection (required)

Anyone who can push a `v*` tag starts a release that signs with the
repository's identity, so **before the first release tag** the repository must
carry two GitHub tag rulesets (repository Settings › Rules › Rulesets; on a
private repository rulesets need a GitHub Team or Enterprise plan):

1. `scripts/release/rulesets/release-tags-create.json`: creating a `v*` tag is
   restricted; only the release managers team (bypass actor) may create one.
2. `scripts/release/rulesets/release-tags-immutable.json`: nobody, including
   release managers and admins, may update (move) or delete a
   `v*` tag (no bypass actors).

They are two rulesets because a bypass actor bypasses every rule of its
ruleset: one ruleset with a release-manager bypass would also let release
managers move and delete tags.

Apply them (a repository admin; this is not done by CI and was not applied by
W4.7). The team slug `release-managers` is an example; use the team that owns
releases:

```sh
team_id=$(gh api orgs/SingularityRD/teams/release-managers --jq .id)
jq --argjson id "$team_id" '.bypass_actors[0].actor_id = $id' \
  scripts/release/rulesets/release-tags-create.json |
  gh api --method POST repos/SingularityRD/autosecops2/rulesets --input -
gh api --method POST repos/SingularityRD/autosecops2/rulesets \
  --input scripts/release/rulesets/release-tags-immutable.json
# check
gh api repos/SingularityRD/autosecops2/rulesets --jq '.[] | [.id, .name, .target, .enforcement] | @tsv'
```

A release manager checks that both rulesets are listed and `active` before
pushing `v<VERSION>-rc.1`.

Customers verify a release, also offline, with `docs/release/dogrulama.md`
(Turkish) and the `verify-release.sh` attached to every release.
