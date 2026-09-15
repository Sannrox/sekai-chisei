# Research: embedded-PostgreSQL envelope for #870

Issue: [#870](https://github.com/Sannrox/sekai-chisei/issues/870)
Discussion: [#906](https://github.com/Sannrox/sekai-chisei/discussions/906)
Predecessor: [#869](https://github.com/Sannrox/sekai-chisei/issues/869)
Date: 2026-09-15
Status: **envelope published**
Hardware: Apple M2 Pro, 32 GiB, Darwin 25.5.0 arm64

Discussion 906 keeps both community runtime backends until an
embedded-PostgreSQL profile is measured: cold start ≤ 5 s, on-disk ≤ 200 MB,
Linux and macOS CI. This note records those numbers. It is not a runtime
engine pick and does not retire SQLite.

## Targets

| Metric | Target | Result |
| --- | --- | --- |
| Cold start | ≤ 5 s | **hold** |
| On-disk footprint | ≤ 200 MB | **hold** |
| macOS | measured here | **hold** |
| Linux CI feasibility | start a Linux PostgreSQL in CI-like packaging | **hold** (Docker Linux image on this host) |

## macOS local server (Homebrew PostgreSQL 17.10)

`cargo run --release --example embedded_postgres_envelope`

`initdb` + `pg_ctl` against a temp data directory. TCP is off;
`unix_socket_directories` is a mode-0700 directory owned by the measuring
user.

| Metric | Measured |
| --- | ---: |
| `initdb` | 602 ms |
| First start (empty cluster) | 137 ms |
| Cold start (existing cluster) | 136 ms |
| Data directory | 40_652_800 B (~39 MiB) |
| Server prefix (`bin`+`lib`+`share`) | 83_345_408 B (~80 MiB) |
| Linked runtime dylibs (incl. ICU data) | 45_325_680 B (~43 MiB) |
| Complete footprint | 169_323_888 B (~161 MiB) |

Cold start 136 ms ≤ 5 s. Complete footprint 161 MiB ≤ 200 MB.

## Linux packaging (Docker `postgres:17-alpine`)

Same example, Docker Engine 29.5.2 on this host (Linux VM).

| Metric | Measured |
| --- | ---: |
| Image size | 114_981_107 B (~110 MiB) |
| First container start to TCP `pg_isready -h 127.0.0.1` | 1_087 ms |

Image 110 MiB ≤ 200 MB. Start 1.08 s ≤ 5 s. The probe uses TCP so it does
not succeed against the image's temporary Unix-socket init server. GitHub
Actions `ubuntu-latest` can run the same image; this run did not execute
on hosted GHA.

## Meaning

The Discussion 906 kill signals are now numbers, not an absence. An
embedded/local PostgreSQL profile can meet cold start and footprint on this
Mac and in Linux-container packaging. Portable ontology SQLite stays distinct
from the control-plane database.

## Consequences

- **#870** is unblocked to retire duplicated runtime storage **after** a
  follow-up implementation chooses the measured profile, ships the migration
  Discussion 906 noted is absent, and keeps ontology SQLite separate.
- Dual SQLite/PostgreSQL remains the shipped community pair until that
  implementation lands. This note does not delete `postgres_*.rs`.
- No vendor name is adopted as the product engine.

## Alternatives rejected here

- Treat the Homebrew prefix or the Alpine image as the one true runtime.
  Rejected: measurement only; #870 still has to pick, migrate, and collapse
  conformance suites.
- Hosted multi-service mesh. Rejected: Discussion 906, not local-first.
- Skip the envelope because SQLite already starts in 24 ms. Rejected: the
  hold was specifically the unmeasured embed profile.
