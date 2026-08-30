# yadgar-store

Engine primitives for every `-db` service: connection pooling, transactions,
migration running, capability probing, credential acquisition and the backup
harness.

**It knows zero entity schemas, and that is the whole point.**

Decisions are recorded in [`yadgarhq/docs`](https://github.com/yadgarhq/docs) —
D7 (capability-level abstraction), D58 (credentials), D6 (backup discipline).

## Why the schemas are somewhere else

Abstracting at the SQL level forces lowest-common-denominator SQL and forfeits
exactly what retrieval needs — vector search, JSON columns, full-text. And a
driver crate holding every module's adapters becomes the new coupling point:
every schema change touches it, every module waits on its release. That is the
monolith one layer down.

So the adapters that encode a module's schema ship inside that module's own
repository, and this crate stops at the engine.

## Capability probing

`"any database"` means `"any database with the required capabilities"`. A module
declares what it needs, the driver probes what the engine offers, and a gap is a
**boot failure** — never a silent degradation. A module that quietly loses vector
search returns worse answers instead of an error, and nothing surfaces it.

Gaps are reported **all at once**. One at a time turns a boot failure into a
guessing game: fix one, redeploy, discover the next.

## Credentials

In-cluster a credential is a mounted Secret; a managed engine has no password at
all and authenticates with a token from a workload identity. Two mechanisms
means what is tested is not what runs — unless the seam that already owns pools
and connections owns this too. Module code sees neither.

`Secret` renders as `Secret(<redacted>)` in `Debug`, because debug formatting
reaches logs, panic messages and tracing spans, and a credential that formats
itself is one that leaks eventually.

## What it does

|                      |                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------- |
| **capability probe** | a module declares what it needs; a gap is a boot failure, and gaps report all at once    |
| **credentials**      | D58's seam — a mounted Secret or a workload-identity token, and module code sees neither |
| **migrations**       | ordering, exactly-once, and refusing a database ahead of the binary                      |
| **pool**             | D4's connection arithmetic, checked at boot                                              |
| **backup**           | restore-verify, because a backup nobody restored is a hypothesis                         |

Every one of these fails at **boot** rather than degrading. That is the shape D7
sets for the capability probe, and the same argument applies to each: a module
that starts against a schema it does not understand, or a pool that will exhaust
its engine under load, fails later and further from the cause.

### The pool ceiling is a correctness property

D4 calls the `-db` twin a **connection concentrator**: N replicas of a logic
service with embedded pools multiply connections against an engine with hard
limits. So `max_connections x replicas` is checked against the engine's limit at
boot, minus a reserve so an operator can still connect when the pools have taken
everything.

The failure this prevents does not look like a configuration error. It looks like
intermittent "too many connections" under load, on whichever service connects
last, and scaling up makes it worse.

### Migrations refuse a database ahead of the binary

The deployment that matters is a rollback: the database sits at version 5 while
the older binary knows 4. Treating that as "nothing pending" runs old code
against a newer schema **silently**, which is how data is corrupted rather than
how an outage happens.

## Status

Capability probing, credentials, migrations, pool configuration and the backup
harness are implemented and tested. What remains needs a live engine: executing
migrations, the MariaDB capability probe, and taking an actual backup.

## Dependencies worth knowing about

**`sqlx` with rustls, never native-tls** (D63). native-tls links OpenSSL, which
means a glibc binary, which means `distroless/cc` and a base ten times larger.

Adding it tripped `cargo deny` twice, and both are recorded in `deny.toml` with
reasoning rather than silenced:

- **`CDLA-Permissive-2.0`** on `webpki-roots` — a _data_ licence for the Mozilla
  CA bundle, which is why it was absent from a list of software licences.
  Permissive, no copyleft, satisfies D24.
- **RUSTSEC-2023-0071** (Marvin Attack, `rsa`) — no fix exists upstream. Accepted
  because the attack recovers a _private_ key by timing decryptions, while
  sqlx-mysql uses `rsa` client-side to _encrypt_ a password with the server's
  public key, and that path is skipped entirely over TLS, which D58 requires.

## Development

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo deny check          # licences, advisories, sources
```

`cargo deny` is not optional discipline here. D24 requires that a permissive
stack stays viable, and O10 requires the licence audit be re-run before adding
any dependency — an instruction that otherwise depends on being remembered.
