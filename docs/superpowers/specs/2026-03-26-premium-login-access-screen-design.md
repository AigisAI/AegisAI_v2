# Premium Login Access Screen Design

## Context

- Issue: `#76`
- Scope: replace the existing login screen with the newer Stitch-driven `AegisAI Premium Access` direction
- Constraint: keep the existing OAuth flow, routing, and auth bootstrap behavior intact

## Goals

- Make the first screen feel closer to a launch-ready commercial security SaaS
- Reduce explanatory copy and shift the visual emphasis to the provider access card
- Preserve explicit trust cues for session-based, provider-scoped, Java-first access

## Screen Direction

- Use a dark, premium access portal composition instead of the previous editorial light landing treatment
- Keep an asymmetric two-column desktop layout with a narrative hero on the left and a stronger auth card on the right
- Compress trust signals into compact chips and shorter support copy
- Keep loading and error states visually integrated into the access card instead of generic alerts

## Non-Goals

- No auth flow changes
- No repositories or scan UI changes
- No app shell redesign in this issue

