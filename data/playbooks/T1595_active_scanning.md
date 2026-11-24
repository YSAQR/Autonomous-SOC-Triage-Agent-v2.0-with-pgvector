# SOC Incident Response Playbook: Active Scanning & Vulnerability Probing (MITRE T1595)

## 1. Detection & Classification (T1595.002)
- **Trigger Conditions:** Bursts of HTTP `401`/`403`/`404` responses targeting sensitive paths (`/.env`, `/.git`, `/wp-login.php`, `/phpmyadmin`, `/admin`) or known reconnaissance User-Agents (`Nikto`, `Nuclei`, `Gobuster`, `Nmap`, `ZGrab`).
- **Severity Guidance:** Usually **Low** to **Medium** if all probes return 404/403 and no sensitive files are exposed; elevate to **High** if any probe returns HTTP 200 or correlates with high AbuseIPDB reputation scores.

## 2. Immediate Containment Commands (Human Analyst Review Required)
Throttle or drop scanner traffic at the firewall or reverse proxy layer.

```bash
# Drop scanning host via iptables
sudo iptables -I INPUT -s <SOURCE_IP> -j DROP

# Verify sensitive dotfiles are blocked in Nginx configuration
sudo grep -rn "\.env\|\.git" /etc/nginx/sites-enabled/
```

## 3. Preventive Hardening (Policy SEC-NET-11)
- Enforce `location ~ /\.(?!well-known).* { deny all; }` in Nginx to block `.env` and `.git` exposure.
- Configure Fail2Ban `nginx-botsearch` jail to automatically rate-limit automated directory scanners.
