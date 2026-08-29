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

## Status

Early. Capability probing and credential resolution are implemented and tested;
pool, migrations and the backup harness are next.

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
