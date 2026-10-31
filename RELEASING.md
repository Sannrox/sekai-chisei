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

Create an annotated, signed tag on the merged release commit:

```text
vX.Y.Z
```

Pre-releases are `vX.Y.Z-rc.N` or `vX.Y.Z-beta.N`. Hotfixes are tagged on
`release/vX.Y`, never on `main` ahead of a minor. A tag is never moved,
deleted, or reused.

## After the tag

The existing `v*` workflow in `.github/workflows/release.yml`:

- verifies the annotated signed tag equals the workspace version
- drafts then publishes a GitHub Release from the matching CHANGELOG section
- uploads the existing `sekai` binary matrix and `compatibility.json`
- builds and pushes the GHCR image by version only (no `latest` tag) and
  prints the image digest
- writes an SBOM, attests provenance, and attaches a family release manifest
  (component, version, git SHA, digests, attestation URLs, gate flags)

Pull requests and `workflow_dispatch` on a non-tag ref dry-run the family
scripts. Dry runs never mint attestations, push images, or create a GitHub
Release.

Allowed tag-signing keys live in `security/release-tag-fingerprints` with
the public key in `security/release-tag-key.asc`.
