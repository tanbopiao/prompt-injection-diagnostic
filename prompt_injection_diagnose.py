#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prompt Injection & Data Exfiltration Diagnostic — local health-check for AI
agent applications.

Read-only survey of an agent project's defenses against prompt injection and
sensitive-data leakage. Produces a report that contains NO secret values and
NO file contents — only filenames, counts, pattern names and recommendations,
so the report is safe to share back for a remediation proposal.

Usage:
    python prompt_injection_diagnose.py [project_dir] [--output DIR] [--json]
    python prompt_injection_diagnose.py [project_dir] --compare OLD_REPORT.json
"""
import argparse
import json
import os
import re
import subprocess
import sys

TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 2

SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

SELF_FIX_HOURS = {
    "PI-NO-STACK": 0,
    "PI-STACK-OK": 0,
    "PI-NO-INSTRUCTION-HIERARCHY": 2,
    "PI-UNSANITIZED-INTERP": 3,
    "PI-EXTERNAL-CONTENT-TRUSTED": 3,
    "PI-TOOL-AUTOEXEC": 4,
    "PI-NO-OUTPUT-FILTER": 3,
    "PI-SECRET-IN-PROMPT": 1,
    "PI-LOG-SENSITIVE": 2,
    "PI-NO-RATE-LIMIT": 2,
    "PI-NO-EGRESS-CONTROL": 3,
}


def fix_hours(fid):
    base = fid.split(":", 1)[0]
    return SELF_FIX_HOURS.get(base, 0)


def finding(fid, severity, title, detail="", advice=""):
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "detail": detail,
        "advice": advice,
        "self_fix_hours": fix_hours(fid),
    }


def safe_read(path, limit=200_000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return ""


def walk_files(root, depth=2, max_files=2000):
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv",
            "site-packages", "dist-info", ".cache", "data", "logs"}
    count = 0
    root_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        if dirpath.rstrip(os.sep).count(os.sep) - root_depth >= depth:
            dirnames[:] = []
        for name in filenames:
            yield os.path.join(dirpath, name)
            count += 1
            if count >= max_files:
                return


CODE_EXTS = (".py", ".js", ".ts")

MODEL_CLIENT_RE = re.compile(
    r"(import\s+(openai|anthropic|dashscope|cohere|litellm|google\.generativeai)|"
    r"from\s+(openai|anthropic|dashscope|cohere|litellm)|"
    r"chat\.completions\.create|messages\.create|generate_content|ChatCompletion)",
    re.IGNORECASE)

# --- prompt template / system prompt files -------------------------------
PROMPT_FILE_HINT = re.compile(
    r"(system[_ -]?prompt|prompt[_ -]?template|SYSTEM_PROMPT|sys_prompt|"
    r"You are (an|a) |You are the )", re.IGNORECASE)
INJECTION_DEFENSE_RE = re.compile(
    r"(ignore (any )?(previous|prior|earlier) instructions?|"
    r"do not follow (instructions|commands) (from|in) (the )?(user|input|document|tool)|"
    r"treat .{0,60}(as|is) (data|untrusted)|untrusted (content|input|text|data)|"
    r"never (follow|execute) instructions (found|contained) in|"
    r"prompt.?injection|指令(优先|层级)|不要执行(用户|文档|工具)(中|内)的指令|"
    r"视为(不可信|数据))", re.IGNORECASE)

# --- user input interpolated into prompts --------------------------------
USER_INPUT_VAR_RE = re.compile(
    r"\b(user_(input|message|query|text|request)|message|query|question|"
    r"prompt_input)\b", re.IGNORECASE)
PROMPT_BUILD_RE = re.compile(
    r"(f['\"]|\.format\(|\+\s*user|template|prompt\s*=\s*['\"`]|messages\s*=\s*\[)",
    re.IGNORECASE)
SANITIZE_GUARD_RE = re.compile(
    r"(sanitiz|escape|validate|strip_|redact|delimit|"
    r"xml_tag|fence|guardrail|injection)", re.IGNORECASE)

# --- external content into context ---------------------------------------
FETCH_RE = re.compile(
    r"(requests\.(get|post)|httpx\.|urllib\.request|fetch\(|"
    r"BeautifulSoup|read_url|scrape|crawl)", re.IGNORECASE)
UNTRUSTED_MARK_RE = re.compile(
    r"(untrusted|external content|treat as data|not (a )?instruction|"
    r"(data|untrusted).{0,20}(fence|tag|delimit)|不可信)", re.IGNORECASE)
CONTEXT_PASS_RE = re.compile(
    r"(context|documents?|pages?|content|results?|tool_output|search_results)",
    re.IGNORECASE)

# --- tool auto-execution --------------------------------------------------
DANGEROUS_EXEC_RE = re.compile(
    r"\b(eval|exec|os\.system|subprocess\.(call|run|Popen)|"
    r"shell\.exec|child_process\.exec)\b")
MODEL_OUTPUT_VAR_RE = re.compile(
    r"\b(response|reply|answer|output|result|model_output|assistant_message|"
    r"completion|tool_call|function_call)\b", re.IGNORECASE)

# --- secrets ---------------------------------------------------------------
SECRET_RE = re.compile(
    r"((api[_ -]?key|secret|token|password|passwd|pwd|private[_ -]?key)"
    r"\s*[=:]\s*['\"][^'\"$\{\s]{8,}['\"]|"
    r"sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})", re.IGNORECASE)

# --- logging of full prompts/responses ------------------------------------
LOG_CALL_RE = re.compile(
    r"(logging\.\w+|logger\.\w+|console\.(log|info|debug)|print\()", re.IGNORECASE)
LOG_PAYLOAD_RE = re.compile(
    r"\b(prompt|messages|system_prompt|response|completion|reply|context)\b",
    re.IGNORECASE)
MASK_GUARD_RE = re.compile(
    r"(mask|redact|anonymi|scrub|truncat|脱敏)", re.IGNORECASE)

# --- rate limiting / egress ------------------------------------------------
RATE_LIMIT_RE = re.compile(
    r"(rate[_ -]?limit|throttl|slowapi|limiter|429|backoff|quota)", re.IGNORECASE)
EGRESS_CONTROL_RE = re.compile(
    r"(allowlist|allow[_ -]?list|whitelist|egress|proxy|"
    r"ALLOWED_(HOSTS|DOMAINS|URLS)|firewall)", re.IGNORECASE)
OUTBOUND_CALL_RE = re.compile(
    r"(requests\.(get|post)|httpx\.|urllib|fetch\(|webhook|smtp|sendmail|"
    r"smtp\.send|email|send_email)", re.IGNORECASE)
SENSITIVE_FILTER_RE = re.compile(
    r"(\b\d{4}[- ]?\d{4}|sk-[A-Za-z0-9]{10,}|"
    r"(id[_ -]?card|passport|credit[_ -]?card|ssn|身份证|银行卡)|"
    r"redact|mask|scrub)", re.IGNORECASE)


def pip_packages():
    pkgs = set()
    try:
        out = subprocess.run([sys.executable, "-m", "pip", "list", "--format=freeze"],
                             capture_output=True, text=True, timeout=60)
        for line in out.stdout.splitlines():
            if "==" in line:
                pkgs.add(line.split("==", 1)[0].strip().lower())
    except Exception:
        pass
    return pkgs


def check_stack(project_dir, pip):
    findings, facts = [], {}
    has_client = bool(pip & {"openai", "anthropic", "dashscope", "cohere",
                             "litellm", "google-generativeai"})
    prompt_files, code_files = [], []
    for fp in walk_files(project_dir, depth=2):
        text = safe_read(fp, 100_000)
        if not text:
            continue
        if fp.endswith(CODE_EXTS):
            code_files.append(fp)
            if MODEL_CLIENT_RE.search(text):
                has_client = True
        if PROMPT_FILE_HINT.search(text):
            prompt_files.append(fp)
    facts["llm_stack_detected"] = has_client
    facts["prompt_like_files"] = [os.path.relpath(p, project_dir) for p in prompt_files[:10]]
    facts["code_files_scanned"] = len(code_files)
    if not has_client and not prompt_files:
        findings.append(finding(
            "PI-NO-STACK", "info",
            "No LLM stack detected in this directory",
            "No model client libraries or prompt-like files found here.",
            "If your agents run elsewhere (another venv, another machine), "
            "run this tool there too — one report per deployment."))
    else:
        findings.append(finding(
            "PI-STACK-OK", "info",
            "LLM stack detected",
            "%d prompt-like file(s), %d code file(s) scanned." % (
                len(prompt_files), len(code_files)),
            "Run this check after every prompt or architecture change — "
            "injection defenses regress silently."))
    return findings, facts, prompt_files, code_files


def check_instruction_hierarchy(project_dir, prompt_files):
    findings, facts = [], {}
    undefended = []
    for fp in prompt_files:
        text = safe_read(fp, 100_000)
        if text and not INJECTION_DEFENSE_RE.search(text):
            undefended.append(os.path.relpath(fp, project_dir))
    facts["prompt_files_without_defense"] = undefended
    if undefended:
        findings.append(finding(
            "PI-NO-INSTRUCTION-HIERARCHY", "medium",
            "%d prompt template(s) with no injection-defense wording" % len(undefended),
            "Files: %s (names only). None of them tell the model to treat "
            "user/document/tool content as data, not instructions." % ", ".join(undefended[:5]),
            "Add an explicit instruction hierarchy to every system prompt: "
            "user and tool content is DATA, never instructions; instructions "
            "inside content must be ignored. This is the cheapest defense "
            "there is — and it measurably reduces successful injections."))
    else:
        findings.append(finding(
            "PI-NO-INSTRUCTION-HIERARCHY", "info",
            "Prompt templates declare an instruction hierarchy",
            "All prompt-like files contain injection-defense wording.",
            "Re-test with real adversarial input periodically — wording "
            "alone is a mitigation, not a guarantee."))
    return findings, facts


def check_unsanitized_interp(project_dir, code_files):
    findings, facts = [], {}
    flagged = []
    for fp in code_files:
        text = safe_read(fp, 100_000)
        if not text:
            continue
        if not (MODEL_CLIENT_RE.search(text) or PROMPT_BUILD_RE.search(text)):
            continue
        if USER_INPUT_VAR_RE.search(text) and PROMPT_BUILD_RE.search(text) \
                and not SANITIZE_GUARD_RE.search(text):
            flagged.append(os.path.relpath(fp, project_dir))
    facts["unsanitized_interp_files"] = flagged
    for rel in flagged:
        findings.append(finding(
            "PI-UNSANITIZED-INTERP:%s" % rel.replace(os.sep, "-"),
            "high",
            "User input flows into prompts with no sanitization: %s" % rel,
            "The file builds prompts from user-controlled variables with no "
            "sanitize/escape/delimit step detected. Content is not included "
            "in this report.",
            "Delimit all user content (XML tags or fenced blocks), state in "
            "the system prompt that tagged content is data, and validate or "
            "strip instruction-like patterns before interpolation."))
    if not flagged:
        findings.append(finding(
            "PI-UNSANITIZED-INTERP", "info",
            "No unsanitized user-input interpolation detected",
            "Prompt-building files either sanitize or delimit user content.",
            "Keep the delimiter convention consistent across all entry points."))
    return findings, facts


def check_external_content(project_dir, code_files):
    findings, facts = [], {}
    flagged = []
    for fp in code_files:
        text = safe_read(fp, 100_000)
        if not text:
            continue
        if FETCH_RE.search(text) and CONTEXT_PASS_RE.search(text) \
                and not UNTRUSTED_MARK_RE.search(text):
            flagged.append(os.path.relpath(fp, project_dir))
    facts["external_content_files"] = flagged
    if flagged:
        findings.append(finding(
            "PI-EXTERNAL-CONTENT-TRUSTED", "high",
            "External content enters model context with no untrusted marking: %d file(s)" % len(flagged),
            "Files: %s (names only). Web pages, documents or tool results "
            "are fetched and passed into prompts without any 'this is data, "
            "not instructions' framing." % ", ".join(flagged[:5]),
            "Wrap every fetched document, web page and tool result in "
            "explicit untrusted-data delimiters, and instruct the model to "
            "ignore instructions found inside them. Indirect injection via "
            "fetched content is the most common real-world attack."))
    else:
        findings.append(finding(
            "PI-EXTERNAL-CONTENT-TRUSTED", "info",
            "External content is marked as untrusted (or none is fetched)",
            "No fetch-into-context flow without untrusted framing was found.",
            "Re-check whenever a new data source or tool is added."))
    return findings, facts


def check_tool_autoexec(project_dir, code_files):
    findings, facts = [], {}
    flagged = []
    for fp in code_files:
        text = safe_read(fp, 100_000)
        if not text:
            continue
        if not MODEL_CLIENT_RE.search(text):
            continue
        if DANGEROUS_EXEC_RE.search(text) and MODEL_OUTPUT_VAR_RE.search(text):
            flagged.append(os.path.relpath(fp, project_dir))
    facts["autoexec_files"] = flagged
    for rel in flagged:
        findings.append(finding(
            "PI-TOOL-AUTOEXEC:%s" % rel.replace(os.sep, "-"),
            "high",
            "Model output can reach dangerous execution: %s" % rel,
            "The file calls a model API and also uses eval/exec/os.system/"
            "subprocess near response-like variables. A successful injection "
            "here becomes remote code execution. Content is not included.",
            "Never execute model output directly. Parse structured tool "
            "calls against a fixed allowlist of actions and arguments, and "
            "require human confirmation for anything destructive."))
    if not flagged:
        findings.append(finding(
            "PI-TOOL-AUTOEXEC", "info",
            "No direct model-output execution detected",
            "No eval/exec/shell calls near model-response variables in "
            "model-calling files.",
            "Keep tool calls schema-validated and allowlisted."))
    return findings, facts


def check_output_filter(project_dir, code_files):
    findings, facts = [], {}
    outbound, filtered = [], []
    for fp in code_files:
        text = safe_read(fp, 100_000)
        if not text:
            continue
        if OUTBOUND_CALL_RE.search(text):
            outbound.append(fp)
            if SENSITIVE_FILTER_RE.search(text):
                filtered.append(fp)
    facts["outbound_files"] = [os.path.relpath(p, project_dir) for p in outbound[:10]]
    facts["outbound_files_with_filter"] = len(filtered)
    if outbound and len(filtered) < len(outbound):
        findings.append(finding(
            "PI-NO-OUTPUT-FILTER", "medium",
            "%d of %d outbound channels have no sensitive-data scrubbing" % (
                len(outbound) - len(filtered), len(outbound)),
            "Files sending data outward (email, webhook, HTTP) without any "
            "key/card/ID-pattern filtering.",
            "Scrub outbound payloads against known sensitive patterns "
            "(API keys, card numbers, ID numbers) before they leave the "
            "process. One injected prompt should not cost you a data breach."))
    elif outbound:
        findings.append(finding(
            "PI-NO-OUTPUT-FILTER", "info",
            "Outbound channels apply sensitive-data filtering",
            "%d outbound file(s), all with pattern-based scrubbing." % len(outbound),
            "Review the patterns quarterly — new data shapes appear with "
            "every new integration."))
    else:
        findings.append(finding(
            "PI-NO-OUTPUT-FILTER", "info",
            "No outbound data channels detected",
            "No email/webhook/HTTP senders found in scanned files.",
            "If the agent sends reports or notifications, run this check "
            "again after adding the channel."))
    return findings, facts


def check_secrets(project_dir, prompt_files, code_files):
    findings, facts = [], {}
    flagged = []
    for fp in list(prompt_files) + code_files:
        text = safe_read(fp, 100_000)
        if not text:
            continue
        m = SECRET_RE.search(text)
        if m:
            flagged.append(os.path.relpath(fp, project_dir))
    facts["secret_like_files"] = flagged
    for rel in flagged:
        findings.append(finding(
            "PI-SECRET-IN-PROMPT:%s" % rel.replace(os.sep, "-"),
            "high",
            "Secret-like literal found in source or prompt file: %s" % rel,
            "A hardcoded key/token/password pattern was detected (the value "
            "itself is NOT included in this report).",
            "Move the secret to an environment variable or secret manager "
            "and rotate the exposed value now — anything committed once "
            "must be treated as compromised."))
    if not flagged:
        findings.append(finding(
            "PI-SECRET-IN-PROMPT", "info",
            "No hardcoded secrets detected",
            "No secret-like literals found in scanned files.",
            "Keep secrets in env vars or a secret manager, and add secret "
            "scanning to CI."))
    return findings, facts


def check_logging(project_dir, code_files):
    findings, facts = [], {}
    flagged = []
    for fp in code_files:
        text = safe_read(fp, 100_000)
        if not text:
            continue
        if LOG_CALL_RE.search(text) and LOG_PAYLOAD_RE.search(text) \
                and not MASK_GUARD_RE.search(text):
            flagged.append(os.path.relpath(fp, project_dir))
    facts["unmasked_log_files"] = flagged
    if flagged:
        findings.append(finding(
            "PI-LOG-SENSITIVE", "medium",
            "%d file(s) log full prompts or responses with no masking" % len(flagged),
            "Files: %s (names only). Prompt/response content in logs "
            "spreads sensitive data to every system that can read the logs."
            % ", ".join(flagged[:5]),
            "Mask or truncate prompt/response payloads in logs, and gate "
            "full-payload logging behind a debug flag that is off in "
            "production."))
    else:
        findings.append(finding(
            "PI-LOG-SENSITIVE", "info",
            "No unmasked prompt/response logging detected",
            "Log calls either avoid full payloads or apply masking.",
            "Spot-check real logs occasionally — masking code rots too."))
    return findings, facts


def check_rate_limit(project_dir, code_files):
    findings, facts = [], {}
    has_guard = any(RATE_LIMIT_RE.search(safe_read(fp, 100_000))
                    for fp in code_files)
    facts["rate_limit_config_found"] = has_guard
    if has_guard:
        findings.append(finding(
            "PI-NO-RATE-LIMIT", "info",
            "Rate limiting or throttling configuration found",
            "Rate-limit-related code or config detected.",
            "Verify limits apply per user and per key, not just globally — "
            "a global cap lets one tenant starve the rest."))
    else:
        findings.append(finding(
            "PI-NO-RATE-LIMIT", "low",
            "No rate limiting detected on model endpoints",
            "No rate-limit/throttle/backoff configuration found while the "
            "project calls model APIs.",
            "Add per-user rate limits. They cap the blast radius of both "
            "abuse and runaway loops — and they are also a cost control."))
    return findings, facts


def check_egress(project_dir, code_files):
    findings, facts = [], {}
    has_control = any(EGRESS_CONTROL_RE.search(safe_read(fp, 100_000))
                      for fp in code_files)
    facts["egress_control_found"] = has_control
    if has_control:
        findings.append(finding(
            "PI-NO-EGRESS-CONTROL", "info",
            "Egress controls detected",
            "Allowlist/proxy/egress configuration found.",
            "Review the allowlist when integrations change — stale entries "
            "are silent holes."))
    else:
        findings.append(finding(
            "PI-NO-EGRESS-CONTROL", "low",
            "No outbound-network allowlist detected",
            "No allowlist, proxy or egress configuration found, while the "
            "project makes outbound calls.",
            "Restrict outbound traffic to an explicit allowlist of hosts. "
            "If an injection ever succeeds, egress control is what turns a "
            "data breach into a blocked request."))
    return findings, facts


def compare_reports(current, old_path):
    """Diff two diagnostic reports by stable finding ID: new/resolved/persisting."""
    with open(old_path, encoding="utf-8") as f:
        old = json.load(f)

    def idmap(rep):
        return {f["id"]: f for f in rep.get("findings", []) if f.get("id")}

    cur, oldm = idmap(current), idmap(old)
    new_ids = sorted(set(cur) - set(oldm))
    resolved_ids = sorted(set(oldm) - set(cur))
    persist_ids = sorted(set(cur) & set(oldm))
    sev_changed = [{"id": i, "from": oldm[i]["severity"], "to": cur[i]["severity"]}
                   for i in persist_ids if oldm[i]["severity"] != cur[i]["severity"]]
    return {
        "compared_against": os.path.abspath(old_path),
        "old_generated_at": old.get("generated_at"),
        "new": [cur[i] for i in new_ids],
        "resolved": [{"id": i, "severity": oldm[i]["severity"], "title": oldm[i]["title"]}
                     for i in resolved_ids],
        "persisting": [cur[i] for i in persist_ids],
        "severity_changed": sev_changed,
    }


def render_markdown(report):
    lines = [
        "# Prompt Injection & Data Exfiltration Diagnostic Report",
        "",
        "Generated: %s  |  Project: %s  |  Tool: v%s (schema v%s)" % (
            report["generated_at"], report["facts"].get("project_dir", ""),
            report.get("tool_version", "?"), report.get("schema_version", "?")),
        "",
        "**Summary:** %d high · %d medium · %d low · %d info" % (
            report["summary"]["high"], report["summary"]["medium"],
            report["summary"]["low"], report["summary"]["info"]),
        "",
        "> %s" % report["note"],
        "",
    ]
    for f in report["findings"]:
        hours = f.get("self_fix_hours")
        hours_txt = " · self-fix ~%s h" % hours if hours else ""
        lines.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
        lines.append("- Finding ID: `%s`%s" % (f.get("id", "?"), hours_txt))
        if f["detail"]:
            lines.append("- %s" % f["detail"])
        if f["advice"]:
            lines.append("- **Advice:** %s" % f["advice"])
        lines.append("")
    cmp_ = report.get("compare")
    if cmp_:
        lines += ["## Comparison with previous report", "",
                  "- Baseline: `%s` (generated %s)" % (
                      cmp_["compared_against"], cmp_.get("old_generated_at") or "unknown"), ""]
        if cmp_["resolved"]:
            lines.append("**Resolved:**")
            for r in cmp_["resolved"]:
                lines.append("- RESOLVED `%s` %s" % (r["id"], r["title"]))
            lines.append("")
        if cmp_["new"]:
            lines.append("**New:**")
            for n in cmp_["new"]:
                lines.append("- NEW `%s` %s" % (n["id"], n["title"]))
            lines.append("")
        if cmp_["severity_changed"]:
            lines.append("**Severity changed:**")
            for s in cmp_["severity_changed"]:
                lines.append("- CHANGED `%s`: %s -> %s" % (s["id"], s["from"], s["to"]))
            lines.append("")
        if cmp_["persisting"]:
            lines.append("**Persisting** (not yet fixed, follow the advice):")
            for p in cmp_["persisting"]:
                lines.append("- `%s` %s" % (p["id"], p["title"]))
            lines.append("")
        if not (cmp_["resolved"] or cmp_["new"] or cmp_["severity_changed"] or cmp_["persisting"]):
            lines.append("No changes between the two runs.", "")
    return "\n".join(lines)


def build_report(project_dir):
    pip = pip_packages()
    all_findings = []
    facts = {"generated_at": __import__("datetime").datetime.now().isoformat(),
             "project_dir": os.path.abspath(project_dir)}
    stack_findings, stack_facts, prompt_files, code_files = check_stack(project_dir, pip)
    all_findings.extend(stack_findings)
    facts.update(stack_facts)

    for fn in (check_instruction_hierarchy, check_unsanitized_interp,
               check_external_content, check_tool_autoexec, check_output_filter,
               check_secrets, check_logging, check_rate_limit, check_egress):
        if fn is check_instruction_hierarchy:
            f, fa = fn(project_dir, prompt_files)
        elif fn is check_secrets:
            f, fa = fn(project_dir, prompt_files, code_files)
        elif fn is check_rate_limit or fn is check_egress:
            f, fa = fn(project_dir, code_files)
        else:
            f, fa = fn(project_dir, code_files)
        all_findings.extend(f)
        facts.update(fa)

    all_findings.sort(key=lambda x: (SEV_RANK.get(x["severity"], 9), x.get("id", "")))
    summary = {s: sum(1 for f in all_findings if f["severity"] == s)
               for s in ("high", "medium", "low", "info")}
    return {
        "report_type": "prompt_injection_diagnostic",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": facts["generated_at"],
        "summary": summary,
        "findings": all_findings,
        "facts": facts,
        "note": ("This report contains NO secret values and NO file contents — "
                 "only filenames, counts, pattern names and recommendations. "
                 "It is safe to share back for a security-remediation proposal."),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Prompt injection & data exfiltration diagnostic (read-only)")
    ap.add_argument("project_dir", nargs="?", default=os.getcwd())
    ap.add_argument("--output", default=None,
                    help="Directory for reports (default: <project_dir>/prompt_injection_diag_reports)")
    ap.add_argument("--compare", metavar="OLD_REPORT.json",
                    help="Compare with a previous JSON report (new/resolved/persisting)")
    ap.add_argument("--json", action="store_true", help="Also print JSON to stdout")
    args = ap.parse_args()

    report = build_report(args.project_dir)
    if args.compare:
        if not os.path.exists(args.compare):
            print("Compare failed: old report not found: %s" % args.compare)
            sys.exit(2)
        try:
            report["compare"] = compare_reports(report, args.compare)
        except Exception:
            print("Compare failed: old report unreadable (%s)" % type(e).__name__)
            sys.exit(2)

    outdir = args.output or os.path.join(args.project_dir, "prompt_injection_diag_reports")
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "prompt_injection_report.md")
    js_path = os.path.join(outdir, "prompt_injection_report.json")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    with open(js_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    s = report["summary"]
    print("Prompt injection & data exfiltration diagnostic complete.")
    print("  high: %d | medium: %d | low: %d | info: %d" % (
        s["high"], s["medium"], s["low"], s["info"]))
    cmp_ = report.get("compare")
    if cmp_:
        print("  compare: %d new | %d resolved | %d persisting" % (
            len(cmp_["new"]), len(cmp_["resolved"]), len(cmp_["persisting"])))
    print("Report: %s" % md_path)
    print("        %s" % js_path)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
