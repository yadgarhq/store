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

  `!` marks a breaking change and implies a major bump; `feat:` implies minor,
  everything else patch. The highest bullet wins.
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
