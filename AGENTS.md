# AGENTS.md

## Project

This repository is for research on:

- Predictive RAM Compression
- Early Decompression

Current stage:

- Brainstorming and rapid experimentation
- Learning and validating observability techniques with eBPF
- Building small, testable probes before designing larger systems

## Immediate Goal

Start from strong eBPF fundamentals and use them to collect signals that can inform compression/decompression policy ideas.

## Working Principles

- Prefer small, runnable prototypes over large speculative designs.
- Measure first, theorize second.
- Keep experiments reproducible with clear build/run instructions.
- Favor kernel tracepoints first, then move to deeper hooks only when justified.

## What Exists Today

- Minimal eBPF hello-world example that hooks `sched_process_fork`
- Prints `hello world <PID>` for each process fork via `bpf_printk`
- Userspace loader using libbpf skeleton flow

See:

- `src/proc_create.bpf.c`
- `src/proc_create.c`
- `README.md`

## Agent Instructions

- Treat this repo as research code: clarity and iteration speed matter.
- For each idea, define:
  - Hypothesis
  - Signal to collect
  - eBPF hook point
  - Expected outcome
  - Quick validation plan
- Keep changes narrowly scoped; do not introduce broad abstractions early.
- Use this C style in handwritten code:

```c
if (condition) {
    // code
}
```

- Update docs when behavior or run commands change.
- Use conventional commits.

## Experiment Loop

1. Pick one hypothesis.
2. Add or modify one probe.
3. Build and run locally.
4. Capture sample output.
5. Summarize what was learned and next question.

## Near-Term Research Directions

- Process lifecycle patterns as lightweight predictors of memory pressure
- Page fault and reclaim signal collection (`mm`/`vmscan` tracepoints)
- Access-pattern hints for deciding early decompression timing
- Overhead evaluation of candidate probes (latency and event volume)

## Non-Goals (for now)

- Production-hardening
- Complex control planes
- Premature optimization before signal quality is understood
