---
title: Live Investigation Demo
description: One human expert + multiple parallel AI investigators = one much more powerful security team. See a live, interactive investigation.
layout: doc
---

# One human expert + many AI investigators = one much more powerful security team

This is a live demo of the **Open Cowork** investigation experience.
A human expert directs the work. A team of specialized AI investigators
runs in parallel — endpoint, network, identity, threat intel, historical,
and a challenger that pressure-tests the conclusions.

The demo below uses **synthetic** data only. No real hosts, accounts, or
destinations are referenced.

<ClientOnly>
  <LiveInvestigationDemo />
</ClientOnly>

## How to read the screen

- **Left** — what the *human* told the team: objective, hypothesis, and constraints.
- **Center** — the AI-generated plan, parallel workers, and a live evidence feed.
- **Right** — current hypotheses with confidence, the Challenger's contradictions,
  AI synthesis, and the **next-best question** the human can answer to keep the
  investigation moving.

## What you're seeing

1. **Plan.** The planner turns the human's objective into a team of focused
   investigators.
2. **Parallel execution.** Each worker runs independently and reports findings
   as soon as they have something solid.
3. **Evidence correlation.** Observations from different domains (process tree,
   network, identity, intel) are automatically linked by shared entities — host,
   account, destination.
4. **Challenger.** A dedicated contrarian agent surfaces what would have to be
   true for the hypothesis to *not* hold, so the human isn't misled by
   coincidence.
5. **Hypothesis state.** Confidence moves up or down based on corroborated
   evidence, with the rationale attached.
6. **Next-best question.** Instead of asking the human to read a transcript, the
   AI proposes the single highest-value question that would most reduce
   uncertainty right now — and continues the moment the human answers.

## The thesis

> One human expert + multiple parallel AI investigators
> = one much more powerful security team.

The human stays in the loop as the **decision-maker and director**. The AI
team handles breadth, speed, and disciplined reasoning — including pushing
back on its own conclusions.
