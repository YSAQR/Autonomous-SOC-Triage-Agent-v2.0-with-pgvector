"""Deterministic log pre-filtering, rule-based baseline scoring, and command sanitization.

Responsibilities:
1. Parse Linux auth.log and Nginx/Apache access logs via compiled regex.
2. Discard benign traffic and batch suspicious events into time windows.
3. Compute SHA-256 content hashes for idempotent re-ingestion.
4. Provide a deterministic rule-based baseline (`evaluate_batch_rules`) for fast triage,
   evidence-based routing, and evaluation benchmarking against the LLM agent.
5. Sanitize LLM-suggested remediation commands against shell injection using `ipaddress`
   validation and strict allowlisted command prefixes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal

LogSourceType = Literal["auth.log", "access.log", "mixed"]

# ---------------------------------------------------------------------------
# Compiled Regular Expressions — Auth Logs (SSH / PAM / sudo)
# ---------------------------------------------------------------------------
_AUTH_TIMESTAMP_RE = re.compile(
    r"^(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-\/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

_SSH_FAILED_PWD_RE = re.compile(
    r"Failed\s+(?:password|publickey|none)\s+for\s+(?:(?P<invalid>invalid\s+user)\s+)?"
    r"(?P<user>[\w.\-@]+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+"
)
_SSH_INVALID_USER_RE = re.compile(
    r"Invalid\s+user\s+(?P<user>[\w.\-@]+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)"
)
_SSH_MAX_AUTH_RE = re.compile(
    r"maximum\s+authentication\s+attempts\s+exceeded\s+for\s+(?:invalid\s+user\s+)?"
    r"(?P<user>[\w.\-@]+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)"
)
_SSH_PAM_FAIL_RE = re.compile(
    r"pam_unix\(sshd:auth\):\s+authentication\s+failure;.*?\brhost=(?P<ip>[0-9a-fA-F:.]+)"
    r"(?:.*?\buser=(?P<user>[\w.\-@]+))?"
)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>[\w.\-@]+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)"
)
_SUDO_ESCALATION_RE = re.compile(
    r"(?P<user>[\w.\-]+)\s*:\s*(?P<detail>"
    r"user\s+NOT\s+in\s+sudoers|"
    r"\d+\s+incorrect\s+password\s+attempts|"
    r"TTY=.*?USER=root\s*;\s*COMMAND=(?P<cmd>.+))"
)

# ---------------------------------------------------------------------------
# Compiled Regular Expressions — Nginx / Apache Combined Access Logs
# ---------------------------------------------------------------------------
_ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+(?P<proto>HTTP/[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*'
    r'(?:"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_WEB_ATTACK_SIGNATURE_RE = re.compile(
    r"(?i)(?:"
    r"\.\./|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|/proc/self|"
    r"union\s+select|union%20select|information_schema|'--|%27\s*or\s*%27|or\s+1=1|sleep\(|benchmark\(|waitfor\s+delay|"
    r"<script|%3cscript|javascript:|onerror=|"
    r";\s*(?:cat|id|whoami|wget|curl|nc|bash|sh)\b|\|\s*(?:id|cat|sh)\b|\$\(|`"
    r")"
)

_SENSITIVE_ENDPOINT_RE = re.compile(
    r"(?i)(?:/\.env|/\.git|/wp-login\.php|/wp-admin|/xmlrpc\.php|/phpmyadmin|"
    r"/admin|/cgi-bin|/actuator|/console|/api/v\d+/auth|/login|/config\.php)"
)

_SUSPICIOUS_UA_RE = re.compile(
    r"(?i)(?:sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|nuclei|hydra|zgrab|ffuf|acunetix)"
)

_BENIGN_STATIC_RE = re.compile(
    r"(?i)\.(?:css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|map)(?:\?.*)?$"
)

_SUSPICIOUS_HTTP_STATUSES = {401, 403, 500, 502, 503}

# Security: Shell-injection metacharacter & allowlist patterns for remediation commands
_SHELL_METACHAR_RE = re.compile(r"(?:[;`|]|&&|\|\||\$\(|\n|\r|>>?)")
_IP_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SAFE_REMEDIATION_PREFIXES = (
    "sudo ufw ",
    "sudo iptables ",
    "sudo fail2ban-client ",
    "sudo usermod -L ",
    "sudo pkill ",
    "sudo journalctl ",
    "sudo visudo ",
    "sudo grep ",
    "ps -ef",
    "ls -la /etc/sudoers",
    "echo \"deny ",
)


@dataclass(slots=True)
class SuspiciousEvent:
    """Normalized representation of a single suspicious log entry."""

    timestamp: datetime
    source_type: Literal["auth.log", "access.log"]
    category: str
    raw_line: str
    source_ip: str | None = None
    username: str | None = None
    endpoint: str | None = None
    http_status: int | None = None


@dataclass(slots=True)
class RuleAssessment:
    """Deterministic rule-based verdict used for routing and evaluation baseline."""

    verdict: Literal["malicious", "benign"]
    severity: Literal["Low", "Medium", "High", "Critical"]
    mitre_attack_id: str
    technique_name: str
    flags: list[str] = field(default_factory=list)
    failed_auth_count: int = 0
    post_failure_success: bool = False
    is_ambiguous: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "severity": self.severity,
            "mitre_attack_id": self.mitre_attack_id,
            "technique_name": self.technique_name,
            "flags": self.flags,
            "failed_auth_count": self.failed_auth_count,
            "post_failure_success": self.post_failure_success,
            "is_ambiguous": self.is_ambiguous,
        }


@dataclass(slots=True)
class ParsedLogBatch:
    """A time-windowed batch of correlated suspicious events."""

    source_type: LogSourceType
    window_start: datetime
    window_end: datetime
    total_lines_ingested: int
    events: list[SuspiciousEvent] = field(default_factory=list)
    extracted_ips: list[str] = field(default_factory=list)
    extracted_usernames: list[str] = field(default_factory=list)
    extracted_endpoints: list[str] = field(default_factory=list)
    category_counts: dict[str, int] = field(default_factory=dict)

    @property
    def suspicious_event_count(self) -> int:
        return len(self.events)

    def build_raw_excerpt(self, max_lines: int = 40) -> str:
        """Return a bounded excerpt of raw suspicious lines for storage and LLM context."""
        return "\n".join(ev.raw_line for ev in self.events[:max_lines])

    def build_triage_summary(self) -> str:
        """Return a compact structured text summary for LLM prompt injection."""
        cat_str = ", ".join(f"{k}: {v}" for k, v in sorted(self.category_counts.items()))
        return (
            f"Log Source: {self.source_type}\n"
            f"Time Window (UTC): {self.window_start.isoformat()} -> {self.window_end.isoformat()}\n"
            f"Suspicious Events: {self.suspicious_event_count} (out of {self.total_lines_ingested} lines)\n"
            f"Event Categories: {cat_str}\n"
            f"Source IPs: {', '.join(self.extracted_ips) or 'None'}\n"
            f"Target Usernames: {', '.join(self.extracted_usernames) or 'None'}\n"
            f"Target Endpoints: {', '.join(self.extracted_endpoints[:15]) or 'None'}\n"
            f"Sample Suspicious Log Lines:\n{self.build_raw_excerpt(max_lines=30)}"
        )


@dataclass(slots=True)
class ParseResult:
    """Complete output of deterministic pre-filtering across an ingested log payload."""

    content_hash: str
    total_lines: int
    benign_discarded: int
    suspicious_total: int
    detected_source: LogSourceType
    batches: list[ParsedLogBatch]


def compute_content_hash(raw_logs: str) -> str:
    """Compute a normalized SHA-256 hash for idempotent log ingestion."""
    normalized = "\n".join(ln.strip() for ln in raw_logs.splitlines() if ln.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def is_valid_ip(value: str) -> bool:
    """Validate an IPv4/IPv6 string strictly using Python's ipaddress module."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def sanitize_remediation_commands(
    commands: list[str],
    allowed_ips: list[str] | None = None,
) -> list[str]:
    """Validate and filter LLM-generated containment commands against shell injection.

    Rejects commands containing shell chaining metacharacters (unless matching a known
    safe Nginx reload template) or unvalidated/malformed IP tokens.
    """
    valid_allowed_ips = {ip for ip in (allowed_ips or []) if is_valid_ip(ip)}
    safe_commands: list[str] = []

    for raw_cmd in commands:
        cmd = raw_cmd.strip()
        if not cmd or len(cmd) > 300:
            continue

        # Allow exact safe Nginx deny + reload pattern only if IP is strictly validated
        nginx_match = re.fullmatch(
            r'echo "deny ([0-9a-fA-F:.]+);" \| sudo tee -a /etc/nginx/conf\.d/soc_blocklist\.conf '
            r"&& sudo nginx -t && sudo systemctl reload nginx",
            cmd,
        )
        if nginx_match:
            ip_val = nginx_match.group(1)
            if is_valid_ip(ip_val) and (not valid_allowed_ips or ip_val in valid_allowed_ips):
                safe_commands.append(cmd)
            continue

        # Block all shell metacharacters (;, &&, ||, |, `, $(), >, <, newlines)
        if _SHELL_METACHAR_RE.search(cmd):
            continue

        # Require a known defensive read-only or containment command prefix
        if not cmd.startswith(_SAFE_REMEDIATION_PREFIXES):
            continue

        # Verify every IP-like token inside the command is a valid IP address
        ip_tokens = _IP_TOKEN_RE.findall(cmd)
        if any(not is_valid_ip(tok) for tok in ip_tokens):
            continue

        safe_commands.append(cmd)

    return safe_commands


def evaluate_batch_rules(batch: ParsedLogBatch) -> RuleAssessment:
    """Deterministic rule-based baseline classifier for routing and evaluation."""
    cats = batch.category_counts
    flags: list[str] = []

    failed_auth = (
        cats.get("ssh_failed_password", 0)
        + cats.get("ssh_invalid_user_failed_auth", 0)
        + cats.get("ssh_invalid_user_probe", 0)
        + cats.get("ssh_pam_auth_failure", 0)
        + cats.get("ssh_max_auth_exceeded", 0)
    )
    root_login = cats.get("ssh_root_login_accepted", 0) > 0
    any_login = cats.get("ssh_login_accepted", 0) > 0 or root_login
    post_failure_success = failed_auth >= 2 and any_login

    sudo_unauth = cats.get("sudo_unauthorized_attempt", 0) + cats.get("sudo_auth_failure", 0)
    sudo_root = cats.get("sudo_root_escalation", 0)
    web_exploit = cats.get("web_exploit_payload", 0)
    web_scanner = cats.get("web_scanner_activity", 0)
    web_sensitive = cats.get("web_sensitive_path_probe", 0)
    http_500 = sum(1 for ev in batch.events if ev.http_status in (500, 502, 503))
    http_401_403 = cats.get("http_401_error_spike", 0) + cats.get("http_403_error_spike", 0)

    if failed_auth >= 5:
        flags.append("BRUTE_FORCE_THRESHOLD_EXCEEDED")
    if post_failure_success:
        flags.append("POST_FAILURE_LOGIN_SUCCESS")
    if root_login:
        flags.append("DIRECT_ROOT_SSH_LOGIN")
    if sudo_unauth > 0:
        flags.append("UNAUTHORIZED_SUDO_ATTEMPT")
    if sudo_root > 0:
        flags.append("SUDO_ROOT_EXECUTION")
    if web_exploit > 0:
        flags.append("WEB_EXPLOIT_PAYLOAD")
    if web_exploit > 0 and http_500 > 0:
        flags.append("WEB_EXPLOIT_WITH_HTTP_500")
    if web_scanner > 0 or web_sensitive > 0:
        flags.append("WEB_RECON_SCANNER")

    # Priority 1: Critical post-exploitation or confirmed compromise
    if post_failure_success or (sudo_unauth > 0 and failed_auth >= 3):
        return RuleAssessment(
            verdict="malicious",
            severity="Critical",
            mitre_attack_id="T1110",
            technique_name="Brute Force",
            flags=flags,
            failed_auth_count=failed_auth,
            post_failure_success=post_failure_success,
            is_ambiguous=False,
        )

    if web_exploit > 0 and http_500 > 0:
        return RuleAssessment(
            verdict="malicious",
            severity="Critical",
            mitre_attack_id="T1190",
            technique_name="Exploit Public-Facing Application",
            flags=flags,
            failed_auth_count=failed_auth,
            post_failure_success=False,
            is_ambiguous=False,
        )

    if sudo_unauth > 0:
        return RuleAssessment(
            verdict="malicious",
            severity="High",
            mitre_attack_id="T1548.003",
            technique_name="Sudo and Sudo Caching",
            flags=flags,
            failed_auth_count=failed_auth,
            post_failure_success=False,
            is_ambiguous=False,
        )

    if web_exploit > 0:
        return RuleAssessment(
            verdict="malicious",
            severity="High",
            mitre_attack_id="T1190",
            technique_name="Exploit Public-Facing Application",
            flags=flags,
            failed_auth_count=failed_auth,
            post_failure_success=False,
            is_ambiguous=False,
        )

    if failed_auth >= 5:
        return RuleAssessment(
            verdict="malicious",
            severity="High",
            mitre_attack_id="T1110",
            technique_name="Brute Force",
            flags=flags,
            failed_auth_count=failed_auth,
            post_failure_success=False,
            is_ambiguous=False,
        )

    if web_scanner > 0 or web_sensitive >= 2 or http_401_403 >= 4:
        return RuleAssessment(
            verdict="malicious",
            severity="Medium",
            mitre_attack_id="T1595",
            technique_name="Active Scanning",
            flags=flags,
            failed_auth_count=failed_auth,
            post_failure_success=False,
            is_ambiguous=True,
        )

    # Low-volume failures (e.g., 1-4 wrong passwords or single sudo command) are ambiguous
    flags.append("LOW_VOLUME_AMBIGUOUS")
    if sudo_root > 0:
        return RuleAssessment(
            verdict="benign",
            severity="Low",
            mitre_attack_id="T1548.003",
            technique_name="Sudo and Sudo Caching",
            flags=flags,
            failed_auth_count=failed_auth,
            post_failure_success=post_failure_success,
            is_ambiguous=True,
        )

    return RuleAssessment(
        verdict="benign" if failed_auth <= 2 and not root_login else "malicious",
        severity="Low" if failed_auth <= 2 and not root_login else "Medium",
        mitre_attack_id="T1110" if failed_auth > 0 else "T1595",
        technique_name="Brute Force" if failed_auth > 0 else "Active Scanning",
        flags=flags,
        failed_auth_count=failed_auth,
        post_failure_success=post_failure_success,
        is_ambiguous=True,
    )


def _parse_auth_timestamp(raw_ts: str, reference_year: int | None = None) -> datetime:
    """Parse syslog (e.g. 'Nov 24 14:22:01') or ISO-8601 timestamps into UTC datetime."""
    cleaned = raw_ts.strip()
    if "T" in cleaned:
        iso_str = cleaned.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_str)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    year = reference_year or datetime.now(timezone.utc).year
    dt = datetime.strptime(f"{year} {cleaned}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def _parse_access_timestamp(raw_ts: str) -> datetime:
    """Parse Nginx/Apache Common Log Format timestamp ('24/Nov/2026:14:22:01 +0000')."""
    try:
        dt = datetime.strptime(raw_ts.strip(), "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def parse_auth_line(line: str, reference_year: int | None = None) -> SuspiciousEvent | None:
    """Inspect a single Linux auth.log line; return SuspiciousEvent or None if benign."""
    match = _AUTH_TIMESTAMP_RE.match(line)
    if not match:
        return None

    proc = match.group("proc").lower()
    msg = match.group("msg")
    ts = _parse_auth_timestamp(match.group("ts"), reference_year=reference_year)

    if "sshd" in proc:
        m = _SSH_FAILED_PWD_RE.search(msg)
        if m:
            cat = "ssh_invalid_user_failed_auth" if m.group("invalid") else "ssh_failed_password"
            return SuspiciousEvent(
                timestamp=ts,
                source_type="auth.log",
                category=cat,
                raw_line=line,
                source_ip=m.group("ip") if is_valid_ip(m.group("ip")) else None,
                username=m.group("user"),
            )

        m = _SSH_MAX_AUTH_RE.search(msg)
        if m:
            return SuspiciousEvent(
                timestamp=ts,
                source_type="auth.log",
                category="ssh_max_auth_exceeded",
                raw_line=line,
                source_ip=m.group("ip") if is_valid_ip(m.group("ip")) else None,
                username=m.group("user"),
            )

        m = _SSH_INVALID_USER_RE.search(msg)
        if m:
            return SuspiciousEvent(
                timestamp=ts,
                source_type="auth.log",
                category="ssh_invalid_user_probe",
                raw_line=line,
                source_ip=m.group("ip") if is_valid_ip(m.group("ip")) else None,
                username=m.group("user"),
            )

        m = _SSH_PAM_FAIL_RE.search(msg)
        if m:
            return SuspiciousEvent(
                timestamp=ts,
                source_type="auth.log",
                category="ssh_pam_auth_failure",
                raw_line=line,
                source_ip=m.group("ip") if is_valid_ip(m.group("ip")) else None,
                username=m.group("user"),
            )

        m = _SSH_ACCEPTED_RE.search(msg)
        if m:
            user = m.group("user")
            cat = "ssh_root_login_accepted" if user == "root" else "ssh_login_accepted"
            return SuspiciousEvent(
                timestamp=ts,
                source_type="auth.log",
                category=cat,
                raw_line=line,
                source_ip=m.group("ip") if is_valid_ip(m.group("ip")) else None,
                username=user,
            )

    if "sudo" in proc:
        m = _SUDO_ESCALATION_RE.search(msg)
        if m:
            detail = m.group("detail")
            if "NOT in sudoers" in detail:
                cat = "sudo_unauthorized_attempt"
            elif "incorrect password" in detail:
                cat = "sudo_auth_failure"
            else:
                cat = "sudo_root_escalation"
            return SuspiciousEvent(
                timestamp=ts,
                source_type="auth.log",
                category=cat,
                raw_line=line,
                username=m.group("user"),
                endpoint=m.group("cmd").strip() if m.group("cmd") else None,
            )

    return None


def parse_access_line(line: str) -> SuspiciousEvent | None:
    """Inspect a single Nginx/Apache access log line; return SuspiciousEvent or None if benign."""
    match = _ACCESS_LOG_RE.match(line)
    if not match:
        return None

    raw_ip = match.group("ip")
    ip = raw_ip if is_valid_ip(raw_ip) else None
    user = match.group("user")
    endpoint = match.group("endpoint")
    status = int(match.group("status"))
    ua = match.group("ua") or ""
    ts = _parse_access_timestamp(match.group("ts"))
    clean_user = None if user in ("-", "") else user

    if _WEB_ATTACK_SIGNATURE_RE.search(endpoint):
        return SuspiciousEvent(
            timestamp=ts,
            source_type="access.log",
            category="web_exploit_payload",
            raw_line=line,
            source_ip=ip,
            username=clean_user,
            endpoint=endpoint,
            http_status=status,
        )

    if _SUSPICIOUS_UA_RE.search(ua):
        return SuspiciousEvent(
            timestamp=ts,
            source_type="access.log",
            category="web_scanner_activity",
            raw_line=line,
            source_ip=ip,
            username=clean_user,
            endpoint=endpoint,
            http_status=status,
        )

    if 200 <= status < 400 and _BENIGN_STATIC_RE.search(endpoint):
        return None

    if status in _SUSPICIOUS_HTTP_STATUSES:
        return SuspiciousEvent(
            timestamp=ts,
            source_type="access.log",
            category=f"http_{status}_error_spike",
            raw_line=line,
            source_ip=ip,
            username=clean_user,
            endpoint=endpoint,
            http_status=status,
        )

    if status == 404 and _SENSITIVE_ENDPOINT_RE.search(endpoint):
        return SuspiciousEvent(
            timestamp=ts,
            source_type="access.log",
            category="web_sensitive_path_probe",
            raw_line=line,
            source_ip=ip,
            username=clean_user,
            endpoint=endpoint,
            http_status=status,
        )

    return None


def parse_and_batch_logs(
    raw_logs: str,
    source_hint: Literal["auto", "auth.log", "access.log"] = "auto",
    window_minutes: int = 5,
    max_events_per_batch: int = 100,
    reference_year: int | None = None,
) -> ParseResult:
    """Filter raw logs via compiled regex and batch suspicious events into time windows."""
    content_hash = compute_content_hash(raw_logs)
    lines = [ln.strip() for ln in raw_logs.splitlines() if ln.strip()]
    total_lines = len(lines)
    suspicious_events: list[SuspiciousEvent] = []
    seen_sources: set[str] = set()

    for line in lines:
        event: SuspiciousEvent | None = None
        if source_hint == "auth.log":
            event = parse_auth_line(line, reference_year=reference_year)
        elif source_hint == "access.log":
            event = parse_access_line(line)
        else:
            event = parse_access_line(line)
            if event is None:
                event = parse_auth_line(line, reference_year=reference_year)

        if event is not None:
            suspicious_events.append(event)
            seen_sources.add(event.source_type)

    # Discard isolated normal ssh_login_accepted if no failures occurred in the same file
    has_auth_failures = any(
        ev.category
        in (
            "ssh_failed_password",
            "ssh_invalid_user_failed_auth",
            "ssh_invalid_user_probe",
            "ssh_pam_auth_failure",
            "ssh_max_auth_exceeded",
        )
        for ev in suspicious_events
    )
    if not has_auth_failures:
        suspicious_events = [
            ev for ev in suspicious_events if ev.category != "ssh_login_accepted"
        ]

    benign_discarded = total_lines - len(suspicious_events)
    if not suspicious_events:
        detected: LogSourceType = (
            source_hint if source_hint in ("auth.log", "access.log") else "mixed"
        )
        return ParseResult(
            content_hash=content_hash,
            total_lines=total_lines,
            benign_discarded=benign_discarded,
            suspicious_total=0,
            detected_source=detected,
            batches=[],
        )

    detected_source: LogSourceType = (
        next(iter(seen_sources))  # type: ignore[assignment]
        if len(seen_sources) == 1
        else "mixed"
    )

    suspicious_events.sort(key=lambda ev: ev.timestamp)
    window_seconds = max(1, window_minutes) * 60
    buckets: dict[int, list[SuspiciousEvent]] = defaultdict(list)

    for ev in suspicious_events:
        bucket_key = int(ev.timestamp.timestamp()) // window_seconds
        buckets[bucket_key].append(ev)

    batches: list[ParsedLogBatch] = []
    for bucket_key in sorted(buckets.keys()):
        bucket_events = buckets[bucket_key]
        for idx in range(0, len(bucket_events), max(1, max_events_per_batch)):
            chunk = bucket_events[idx : idx + max_events_per_batch]
            win_start = chunk[0].timestamp
            win_end = max(chunk[-1].timestamp, win_start + timedelta(seconds=1))
            batch_sources = {ev.source_type for ev in chunk}
            batch_source: LogSourceType = (
                next(iter(batch_sources))  # type: ignore[assignment]
                if len(batch_sources) == 1
                else "mixed"
            )

            ips = list(dict.fromkeys(ev.source_ip for ev in chunk if ev.source_ip))
            usernames = list(dict.fromkeys(ev.username for ev in chunk if ev.username))
            endpoints = list(dict.fromkeys(ev.endpoint for ev in chunk if ev.endpoint))
            cat_counts = dict(Counter(ev.category for ev in chunk))

            batches.append(
                ParsedLogBatch(
                    source_type=batch_source,
                    window_start=win_start,
                    window_end=win_end,
                    total_lines_ingested=total_lines,
                    events=chunk,
                    extracted_ips=ips,
                    extracted_usernames=usernames,
                    extracted_endpoints=endpoints,
                    category_counts=cat_counts,
                )
            )

    return ParseResult(
        content_hash=content_hash,
        total_lines=total_lines,
        benign_discarded=benign_discarded,
        suspicious_total=len(suspicious_events),
        detected_source=detected_source,
        batches=batches,
    )
