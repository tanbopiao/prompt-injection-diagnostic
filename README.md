# Prompt Injection & Data Exfiltration Diagnostic

Free, read-only health-check for AI agent applications: how well is your
deployment defended against **prompt injection** and **sensitive-data
leakage** — the two failure modes that turn a helpful assistant into a
liability.

Part of the [Huodou diagnostic package family](https://www.huodouai.com/sop-demo/)
(memory persistence · agent environment · SOP document library · cost runaway ·
retrieval quality · answer trust · drift watch · prompt injection).

## Why

Most agent projects have **no systematic view** of their injection surface:

- user input flows straight into prompt templates;
- fetched web pages and tool results enter the context with no "this is data,
  not instructions" framing;
- model output is executed or relayed outward with no scrubbing.

When an injection succeeds, the damage is bounded by whatever else is missing:
egress control, output filtering, rate limits. This tool surveys all of it in
one read-only pass and produces a prioritized report.

## What it checks

Every finding has a **stable ID** (e.g. `PI-UNSANITIZED-INTERP:app.py`,
`PI-SECRET-IN-PROMPT:config.py`) and a rough self-fix estimate in person-hours.

| Finding ID | Severity | What it means |
|---|---|---|
| `PI-NO-INSTRUCTION-HIERARCHY` | medium | Prompt templates with no injection-defense wording (no "treat content as data, not instructions") |
| `PI-UNSANITIZED-INTERP:<file>` | high | User input interpolated into prompts with no sanitize/escape/delimit step |
| `PI-EXTERNAL-CONTENT-TRUSTED` | high | Fetched web pages / documents / tool results enter context with no untrusted marking |
| `PI-TOOL-AUTOEXEC:<file>` | high | Model output can reach `eval` / `exec` / `os.system` / `subprocess` — injection becomes code execution |
| `PI-SECRET-IN-PROMPT:<file>` | high | Hardcoded key/token/password literal in source or prompt files (value never included in the report) |
| `PI-NO-OUTPUT-FILTER` | medium | Outbound channels (email/webhook/HTTP) with no sensitive-data scrubbing |
| `PI-LOG-SENSITIVE` | medium | Full prompts/responses logged with no masking |
| `PI-NO-RATE-LIMIT` | low | No rate limiting on model endpoints (abuse amplification) |
| `PI-NO-EGRESS-CONTROL` | low | No outbound-network allowlist (exfiltration channel stays open) |
| `PI-STACK-OK` / `PI-NO-STACK` | info | LLM stack detected / not detected in the scanned directory |

## Quick start

```bash
python prompt_injection_diagnose.py /path/to/your/agent/project
```

Report written to `prompt_injection_diag_reports/prompt_injection_report.md`
(and `.json` for machine reading). Findings are sorted high → medium → low →
info, each with concrete advice.

## Prove the fix worked

Fix the high-severity items, then re-run with:

```bash
python prompt_injection_diagnose.py /path/to/project --compare prompt_injection_diag_reports/prompt_injection_report.json
```

The tool diffs by stable finding ID and lists what was **resolved**, what is
**new**, what changed severity, and what is **persisting**. Your acceptance
criterion: **high-severity findings N → 0**, verified by the tool itself.
Pair it with [Drift Watch](https://www.huodouai.com/whitepaper/drift-watch-package-20261125.html)
to keep that zero from drifting back.

## Privacy

- **Read-only**: the tool never modifies your files.
- **Offline**: no data leaves your machine (the only subprocess call is
  `pip list` to detect installed libraries).
- **Report contains no secrets and no file contents** — only filenames,
  counts, pattern names and recommendations. It is explicitly designed to be
  safe to share.

## Requirements

- Python 3.8+, standard library only, no dependencies to install.

## Send the report back

Email the report to **195162494@qq.com** (individuals and companies welcome)
and we will return a written security-remediation proposal: instruction
hierarchy and delimiting first, then execution guards, egress control and
monitoring.

## License

MIT — see [LICENSE](LICENSE).
