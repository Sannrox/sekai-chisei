# Releasing sekai-chisei

Family versioning, tagging, and release policy:
[tenkai ADR 0040](https://github.com/Sannrox/tenkai/blob/main/docs/decisions/0040-family-versioning-and-release-policy.md).

This page is sekai-chisei-local: how a maintainer prepares and tags **this**
repository. Agents never push `v*` tags.

## Who cuts a tag

After the version-bump pull request merges, the maintainer creates an
annotated, signed `vX.Y.Z` tag with the registered release-signing key.
The tag must equal the workspace version in the root `Cargo.toml`
`[package]` table. The workflow refuses unsigned or lightweight tags.

## Prepare

1. Choose the target version. Do not invent one in a feature pull request.
2. Draft notes with `scripts/changelog-draft.sh`. Pull requests never edit
   `CHANGELOG.md`; the release step writes the section from merged work.
3. Land the version-bump pull request. The workspace version and CHANGELOG
   heading move together.

## Tag

Create an annotated, signed tag on the merged release commit on `main`:

```text
vX.Y.Z
```

A tag is never moved, deleted, or reused. The tagged commit must be on
`main`; the workflow refuses any other commit.

## Release candidates

Cut `vX.Y.Z-rc.N` (or `vX.Y.Z-beta.N`) before the final tag:

1. Land a version-bump pull request that sets the workspace version to
   `X.Y.Z-rc.N` and adds a `## [X.Y.Z-rc.N]` section to `CHANGELOG.md`.
   The final `vX.Y.Z` needs its own section; it never reuses the rc notes.
2. Tag `vX.Y.Z-rc.N` on that commit.
3. The release publishes as a GitHub pre-release and is never marked latest.

A failed release candidate costs only an rc number. A final tag on a commit
whose workspace version is still `X.Y.Z-rc.N` is refused.

## Start, retry, and dry-run

A `v*` tag push runs `.github/workflows/release-dispatch.yml`. It only runs
`gh workflow run release.yml --ref main -f tag=<tag>`, so the release always
runs **main's** `release.yml`, never the copy at the tagged commit.

`release.yml` refuses a tagged run that does not start from `main`. It then:

- checks out the tag and fetches the annotated tag object
- verifies the signed tag with main's `scripts/verify-release-tag.sh` and
  main's allowed keys against the tagged commit's `Cargo.toml`
- requires the tagged commit to be on `main`
- builds, packages, tags images, and writes the manifest `git_sha` from that
  commit, and creates the release with `gh release create <tag> --verify-tag`
- drafts the GitHub Release from the matching CHANGELOG section, uploads the
  `sekai` binary matrix and `compatibility.json`, pushes the GHCR image by
  version only (no `latest` tag), records its digest, writes an SBOM, attests
  provenance, and publishes only after every asset is attached

To retry a failed release, fix the workflow on `main` and run it again for the
same tag:

```sh
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

A re-run resumes the draft release. It refuses a release that is already
published, both before it builds and before it publishes; cut a new version
instead. One run per tag executes at a time.

Pull requests and `workflow_dispatch` without a tag dry-run the family
scripts on that ref. Dry runs never mint attestations, push images, or touch a
GitHub Release.

## Provenance

Attestations record the workflow that built the artifacts, which is main's
`release.yml` at `refs/heads/main`, not the tag. The source is pinned by the
signed tag and by the manifest `git_sha`, which is the tagged commit.

Allowed tag-signing keys live in `security/release-tag-fingerprints` with
the public key in `security/release-tag-key.asc`. A tagged run uses the copies
on `main`.
