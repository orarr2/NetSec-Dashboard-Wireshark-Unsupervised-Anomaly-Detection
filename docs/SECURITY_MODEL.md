# Security model

Four questions, four answers.

## 1. Who can reach the stack from the internet?

Only SSH (port 22). Everything else is bound to the Tailscale interface (`100.68.246.54`) or to loopback (`127.0.0.1`). The Oracle Cloud firewall REJECTs anything that would try to reach the app ports from the public interface (verified with an external port scan; 22 returns open, 443/5200/8080/5678/8766/11434 all filtered).

## 2. Who can reach the stack from Tailscale?

Anyone whose device is signed into your Tailscale account. The tailnet currently has:
- `netsec-agent` (VM)
- `iphone-13-mini`
- `or-pc-1` (laptop)
- `or-pc` (offline)

Adding a device requires either your Tailscale password + email + 2FA, or an admin-console-issued auth key.

## 3. What auth is layered on each service?

| Service | URL / port | Auth | Failure mode |
|---|---|---|---|
| Portal | `/` on 443 | Caddy basicauth (bcrypt) | 401 |
| RAG | `/rag/` on 443 | Caddy basicauth (bcrypt) | 401 |
| Companion | `/chat/` on 443 | Caddy basicauth (bcrypt) | 401 |
| n8n | 5678 | n8n's own login (email+password) | 401 |
| Ingest API upload | 8766 | HMAC-SHA256 per request | 403 |
| Ingest API health | 8766 `/healthz` | none | 200 |
| Ollama | 11434 (loopback) | none | not reachable from outside the VM host |
| SSH | 22 | pubkey only, no passwords | connection dropped |

## 4. What happens on repeated failures?

**SSH:** `sshd` accepts pubkey only; `PasswordAuthentication no`. Brute-force attempts get rejected instantly (no password to guess). Currently ~5,000 attempts/day from ~100 IPs. Ideal follow-up: close 22 to Tailscale only (currently deferred - needs Oracle Console recovery path documented first).

**Caddy basicauth:** `fail2ban` watches Caddy's systemd journal for `msg:"auth provider returned error"`. Five failures within 10 minutes triggers a 1-hour iptables ban of the source IP. On the tailnet this rarely fires (the auth is remembered per browser session), but it defends against a compromised tailnet member trying to brute-force basicauth.

**n8n:** n8n has its own rate-limiter and account lockout.

**Ingest API HMAC:** every request must carry a `signature: HMAC-SHA256(payload, secret)` header where `secret` is the per-sensor secret in the DB. A wrong signature gives 403 without leaking the correct one; there is no "wrong password" quota because there is no password.

## Cert model

TLS on 443 uses a Let's Encrypt certificate issued by Tailscale (they own the `*.tail<id>.ts.net` domain and are an ACME account for it). The cert is short-lived (90 days) and renewed weekly by `netsec-tls-renew.timer` calling `tailscale cert`. Caddy reloads it in place without downtime.

The cert's SAN is only `netsec-agent.tail37ac21.ts.net`. Reaching the stack by the raw IP or the short hostname still works but shows a browser warning (the certificate name does not match).

## Secrets on the VM

| File | Contents | Perm |
|---|---|---|
| `/etc/default/netsec-caddy` | `BASIC_AUTH_USER=`, `BASIC_AUTH_HASH=` | 600, root |
| `/home/ubuntu/netsec/deploy/.env` | Compose reads `BASIC_AUTH_*`, `N8N_ENCRYPTION_KEY`, `SMTP_*`, provider API keys | 600, ubuntu |
| `/etc/netsec-tls/*.key` | Let's Encrypt private key | 600, root |
| `~/.ssh/authorized_keys` | Your pubkeys | 600, ubuntu |
| `/srv/netsec/db/netsec.db` -> `sensors` table | HMAC secret per sensor | file: 644 root, table read via API |
| `docker volume n8n_data` | Any credentials you configured in n8n (Gmail app-password etc) | root docker volume |

Never in git: `.env`, `netsec-tls/`, `sensors.hmac_secret` values, `n8n_data`.

## Data at rest

- SQLite files are unencrypted disk.
- Docker volumes are unencrypted disk.
- The VM disk itself is Oracle-managed (encrypted at rest by Oracle).

If someone gained root on the VM they would see all NetSec data plus the Caddy hash (not the plaintext password). They would not gain access to your Tailscale account or your laptop.

## Threats mitigated

- **Internet-side scanning of app ports.** Blocked by interface binding + firewall.
- **Brute-force of the portal.** Rate-limited by fail2ban.
- **Anyone-on-the-internet clicking the portal URL.** Impossible: DNS name only resolves in your tailnet.
- **Stolen phone with unlocked Tailscale.** They get to the portal but hit basicauth. If they knew the password they would see NetSec data (design accepted risk - remove the phone from tailnet in the admin console if lost).
- **A malicious server on your subnet.** No direct threat: Tailscale is peer-to-peer over WireGuard; the local subnet is not the tailnet.
- **Malware on the laptop.** Would need to grab the SSH key and Tailscale credentials to reach the VM. SSH key is passphrase-protected (recommended).

## Threats NOT mitigated

- **Compromised Tailscale account.** The whole tailnet becomes reachable to the attacker. Turn on 2FA in Tailscale admin.
- **Ollama prompt injection.** The Companion happily runs any prompt you send. No isolation between different chats' contexts (though each chat is its own thread on the model - one chat cannot see another chat's history via prompt).
- **A malicious PCAP crafted to crash tshark.** Tshark is a large parser and has had CVEs. The worker runs in a docker container, but a memory-corruption CVE could still spread within the container. Mitigate: keep tshark updated (`sudo apt upgrade`).
- **A malicious file dropped into Companion.** The file extractor reads bytes; PDF/DOCX libraries have had CVEs. Attach only files you trust. The extraction runs inside the Companion venv but the process runs as `ubuntu`; a full escape would need a kernel bug.
