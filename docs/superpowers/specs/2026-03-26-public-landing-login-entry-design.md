# Public Landing Page And Login Entry Flow Design

## Context

- Issue: `#77`
- Scope: introduce a public SaaS landing page at `/` and reposition `/login` as a focused secure access page
- Constraint: keep the existing OAuth flow, auth bootstrap behavior, and protected workspace routes intact

## Goals

- Make AegisAI feel like a real commercial SaaS product before authentication
- Separate product introduction from the secure access step so each screen has one clear job
- Align the public entry flow with the approved light, premium Stitch direction

## Screen Direction

- `/` becomes a public editorial landing page with product narrative, trust framing, workflow explanation, and provider entry CTA
- `/login` becomes a short, high-confidence secure access page with provider actions and session status handling
- Protected workspace routes remain dedicated to authenticated product use and keep their existing paths

## Information Architecture

- Landing page sections: public nav, hero, trust strip, workflow, assurance, final CTA, footer
- Login page sections: compact top bar, narrative copy, trust strip, provider access card, session/error states
- Routing order: public landing, public login, then protected shell routes

## Non-Goals

- No changes to OAuth endpoints or backend auth contracts
- No redesign of repositories, scans, or dashboard in this issue
- No protected app shell redesign in this issue
