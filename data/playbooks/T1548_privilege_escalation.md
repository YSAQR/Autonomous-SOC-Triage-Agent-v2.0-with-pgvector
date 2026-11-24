# SOC Incident Response Playbook: Abuse Elevation Control Mechanism — Sudo Escalation (MITRE T1548.003)

## 1. Detection & Classification (T1548.003)
- **Trigger Conditions:** `user NOT in sudoers`, repeated `incorrect password attempts` in `sudo`, or unauthorized `USER=root ; COMMAND=...` executions (especially targeting `/etc/shadow`, `/etc/sudoers`, or reverse shells) by service accounts such as `www-data` or `deploy`.
- **Severity Guidance:** Any `sudo` attempt from a non-interactive web/service account (`www-data`, `nginx`, `postgres`) is **Critical** as it indicates likely post-exploitation host compromise.

## 2. Immediate Containment Commands (Human Analyst Review Required)
Isolate the affected account and preserve forensic evidence prior to cleanup.

```bash
# Lock the compromised local account immediately
sudo usermod -L <COMPROMISED_USER>

# Inspect running processes owned by the suspect user
ps -ef | grep -E "^<COMPROMISED_USER>\b"

# Audit /etc/sudoers and /etc/sudoers.d for unauthorized modifications
sudo visudo -c && ls -la /etc/sudoers.d/
```

## 3. Forensic Triage & Recovery (Policy SEC-PRIV-02)
- Check `last -a`, `/var/log/auth.log`, and `crontab -l -u <COMPROMISED_USER>` for persistence mechanisms.
- Verify integrity of `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers`.
- Rotate SSH keys, database credentials, and API tokens accessible to the compromised service account.
