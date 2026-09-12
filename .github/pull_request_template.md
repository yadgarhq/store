<!--
  The sections below are CHECKED BY CI, not merely suggested. `ci-pr` fails when
  one is missing or left empty, so a template that nobody fills in cannot merge.

  Delete nothing. Answer briefly — two lines each is usually enough.
-->

## What

<!-- What changed, in a sentence or two. Not a restatement of the diff. -->

## Why

<!--
  The reason, not the mechanism. If this follows from a decision or an open
  question in the record, name it (D42, O19) — that is what makes the record
  worth keeping.
-->

## Changelog

<!--
  Conventional Commits bullets, ONE PER LINE — every line under this heading is
  parsed, so a wrapped bullet fails. Examples:

    - feat: return partial results when one provider is unhealthy
    - fix: a metadata leak in the audit relay
    - feat!: drop the by-name arm of GetWikiPage

  The bump follows Conventional Commits, classified by `bump_for` in `scripts/pr_body.py` (`yadgarhq/actions`): a `!` bullet classifies as major, a `feat:` bullet classifies as minor, every other bullet classifies as patch. The Changelog's bump is the highest classification among its bullets.

  Check the latest `v*` tag's major version.

  If that major version is 0, the ladder shifts down one step. This shift runs in `ci-pr.yaml`'s `version` job (`yadgarhq/actions`), not in `bump_for`. A major-classified bullet then bumps MINOR. Every other bullet then bumps PATCH.

  If that major version is 1 or higher, the classification applies unshifted. A major-classified bullet bumps MAJOR. A minor-classified bullet bumps MINOR. A patch-classified bullet bumps PATCH.
-->

## Verification

<!--
  How you know it works. "CI is green" counts only when CI actually covers it;
  say so if it does not, and say what you ran instead.
-->

## Risk

<!--
  What breaks if this is wrong, and how it is undone. "None" is a valid answer
  and is worth writing rather than leaving blank.
-->
