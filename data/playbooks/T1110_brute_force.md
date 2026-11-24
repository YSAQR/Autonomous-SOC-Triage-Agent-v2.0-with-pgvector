# SOC Incident Response Playbook: SSH Brute Force & Credential Stuffing (MITRE T1110)

## 1. Detection & Classification (T1110.001 / T1110.003)
- **Trigger Conditions:** Repeated `Failed password`, `Invalid user`, or `maximum authentication attempts exceeded` events in `/var/log/auth.log` from one or more external IPs within a 5-minute window.
- **Severity Escalation:** Escalate immediately to **Critical** if an `Accepted password` or `Accepted publickey` for `root` or a privileged service account follows brute-force failures from the same source IP.
- **Threat Intel Correlation:** Cross-check source IPs against AbuseIPDB (score >= 50 indicates high-confidence malicious infrastructure) and AlienVault OTX pulses.

## 2. Immediate Containment Commands (Human Analyst Review Required)
Before executing any command, verify the source IP is not an authorized corporate VPN or jump host.

```bash
# Block offending IP via UFW firewall
sudo ufw insert 1 deny from <SOURCE_IP> to any comment 'SOC-T1110-SSH-BruteForce'

# Alternative: Ban immediately via Fail2Ban sshd jail
sudo fail2ban-client set sshd banip <SOURCE_IP>

# Terminate active sessions if root or compromised user logged in
sudo pkill -KILL -u <COMPROMISED_USER>
```

## 3. Hardening & Eradication (Policy SEC-AUTH-04)
- Disable direct root SSH login (`PermitRootLogin no`) and enforce key-based authentication (`PasswordAuthentication no`) in `/etc/ssh/sshd_config`.
- Rotate credentials and audit `~/.ssh/authorized_keys` for any account with a successful login during the attack window.
- Review `/var/log/auth.log` for lateral movement or post-login `sudo` execution.
