# Cloud Deployment - running the automation stack 24/7

`docs/AUTOMATION_QUICKSTART.md` describes running the automation stack on
your own machine. That works, but it only triages PCAPs while your laptop
is on and Docker Desktop is open. This document describes the deployment
that removes that limitation: the same two containers running on a free
Oracle Cloud ARM VM, reachable only over a private Tailscale network.

Nothing here changes the application code. It is the same
`automation/docker-compose.yml`, the same `judge_api` image, and the same
workflow JSON - only the host changed.

> **Before making this repository public**, scrub the IP addresses and the
> instance name from this file. They are infrastructure addresses for a
> live machine.

---

## Why a cloud VM

| | laptop | Oracle Always Free VM |
|---|---|---|
| Availability | only while Docker Desktop runs | 24/7 |
| Cost | free | free (Always Free tier, no card charge) |
| RAM available to the stack | shared with everything else | 24GB dedicated |
| Cores | shared | 4 dedicated |

The practical difference: a PCAP dropped into `incoming/` at 3am gets
triaged at 3am.

---

## The machine

| property | value |
|---|---|
| Display name | `netsec-agent` |
| Region | `il-jerusalem-1` (Israel Central), AD-1 |
| Shape | `VM.Standard.A1.Flex` |
| Resources | 4 OCPU / 24GB RAM / 100GB boot volume |
| OS | Ubuntu 24.04 LTS, **aarch64** |
| Public IP | `82.70.253.253` (SSH only) |
| Tailscale IP | `100.68.246.54` (everything else) |
| Project path | `~/netsec` |

`VM.Standard.A1.Flex` at 4 OCPU / 24GB consumes the entire Always Free ARM
allowance for the tenancy (3,000 OCPU-hours and 18,000 GB-hours per month).
A second A1 instance cannot be created alongside it.

SSH in with:

```bash
ssh -i ~/.ssh/netsec-agent.key/ssh-key-2026-07-12.key ubuntu@82.70.253.253
```

---

## ARM64 compatibility

The VM is aarch64, not x86-64. This was the main risk going in, because
`judge_api` installs the project's `requirements.txt` at container startup
and a missing wheel means compiling numerical libraries from source.

It is a non-issue. Every pinned dependency publishes a manylinux aarch64
wheel:

| package | wheel |
|---|---|
| `numpy==2.4.6` | `manylinux_2_27_aarch64` |
| `pandas==3.0.3` | `manylinux_2_24_aarch64` |
| `scikit-learn==1.9.0` | `manylinux_2_27_aarch64` |
| `scipy==1.17.1` | `manylinux_2_27_aarch64` |
| `torch==2.12.1` | `manylinux_2_28_aarch64` |

Only `manuf==1.1.5` is source-only, and it is pure Python that builds in
seconds against the `gcc` already present in the `judge_api` image.

To re-check this after a dependency bump, without installing anything:

```bash
docker run --rm -v $PWD/requirements.txt:/req.txt python:3.11-slim \
  bash -c "pip install --dry-run --only-binary=:all: -r /req.txt"
```

`n8nio/n8n:latest` publishes a native arm64 image, so it needs no special
handling either.

---

## Network model: Tailscale only

Neither n8n nor `judge_api` is exposed to the internet. The only port
reachable on the public IP is 22.

```
your laptop  ──(Tailscale, WireGuard)──►  netsec-agent
100.78.253.22                             100.68.246.54:5678  n8n
                                          100.68.246.54:8765  judge_api

the internet ────────────────────────►    82.70.253.253:22    SSH only
                                          82.70.253.253:5678  no listener
                                          82.70.253.253:8765  no listener
```

Three things are required to make this hold, and missing any one of them
silently breaks it.

### 1. Bind the published ports to the Tailscale IP

`automation/docker-compose.yml` publishes on all interfaces. Override it
on the VM with `automation/docker-compose.override.yml`:

```yaml
services:
  n8n:
    ports: !override
      - "100.68.246.54:5678:5678"
    environment:
      - N8N_HOST=100.68.246.54
  judge_api:
    ports: !override
      - "100.68.246.54:8765:8765"
```

**The `!override` tag is not optional.** Compose *merges* list-valued keys
across files rather than replacing them. Without the tag, the base file's
`0.0.0.0:5678` mapping survives alongside the new one, and the container
fails to start with `failed to bind host port: address already in use`.

### 2. Let Tailscale traffic past the local firewall

Oracle's Ubuntu image ships an `iptables` INPUT chain ending in a
catch-all REJECT, so packets arriving on `tailscale0` are dropped even
though the interface itself is up. Insert the exceptions before that
REJECT and persist them:

```bash
sudo iptables -I INPUT 5 -i tailscale0 -j ACCEPT
sudo iptables -I INPUT 5 -p udp --dport 41641 -j ACCEPT
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

UDP 41641 lets Tailscale establish a direct connection. Without it the
tunnel still works, but every packet is relayed through a DERP server.

### 3. Leave the Oracle Security List alone

The VCN's default security list allows only ingress on 22. Do not open
5678 or 8765 there. Note that Docker's published ports bypass the INPUT
chain via DNAT, so the cloud-level rule is the backstop that matters if
the bind in step 1 is ever wrong.

Verify both directions after any change:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://100.68.246.54:5678/    # expect 200
curl -s -o /dev/null -w "%{http_code}\n" http://82.70.253.253:5678/    # expect 000
```

---

## Deploying from scratch

Assuming a fresh Always Free ARM instance running Ubuntu 24.04.

### 1. Docker

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker ubuntu
sudo systemctl enable --now docker
```

`systemctl enable` plus the `restart: unless-stopped` already in the
compose file means the stack returns on its own after a reboot. There is
nothing to run at boot.

### 2. Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sudo sh
sudo tailscale up --hostname=netsec-agent
```

Then apply the firewall rules from the section above.

### 3. The project

Copy the repo across, excluding local capture output:

```bash
tar --exclude='netsec_sessions' --exclude='__pycache__' --exclude='.git' \
    -cf - app llm_judge attack_tests tools tests docs automation \
          incoming processed requirements.txt README.md \
  | ssh -i <key> ubuntu@<public-ip> 'mkdir -p ~/netsec && tar -xf - -C ~/netsec'
```

`automation/` is gitignored, so it will not arrive via `git clone`. It has
to be copied directly, and it carries `.env` with the Groq key.

### 4. Bring it up

```bash
cd ~/netsec/automation
docker compose up -d
```

First start takes about 5 minutes while `judge_api` installs the project
dependencies into the `judge_api_deps` named volume. Subsequent restarts
are immediate. Confirm with:

```bash
docker compose ps                              # both Up, judge_api healthy
curl -s http://100.68.246.54:8765/health       # {"status":"ok", ...}
```

---

## Importing the workflow

The CLI import is the reliable path, but the shipped template needs one
adjustment first:

```
SQLITE_CONSTRAINT: NOT NULL constraint failed: workflow_entity.id
```

Current n8n builds require an explicit `id` on CLI import, and
`automation/n8n_workflows/mvp_triage_email.json` does not have one. Stamp
one onto a *copy* rather than editing the template:

```bash
python3 -c "
import json
d = json.load(open('/home/ubuntu/netsec/automation/n8n_workflows/mvp_triage_email.json'))
d['id'] = 'netsecmvptriage01'
json.dump(d, open('/tmp/wf.json','w'), indent=2)"

docker cp /tmp/wf.json netsec-n8n:/tmp/wf.json
docker exec -u node netsec-n8n n8n import:workflow --input=/tmp/wf.json
docker exec -u node netsec-n8n n8n list:workflow
```

The workflow imports inactive. Activation is deliberate and separate.

---

## Credentials

Recent n8n releases ignore `N8N_BASIC_AUTH_ACTIVE` and friends. The first
visit to `http://100.68.246.54:5678` prompts for an owner account instead.
Create it there; the env vars in the compose file have no effect.

The Gmail SMTP credential can be re-entered by hand (see
`AUTOMATION_QUICKSTART.md` for the field values), or migrated from an
existing local n8n instance. Migration only works because both instances
read the same `N8N_ENCRYPTION_KEY` from the same copied `.env` - n8n
encrypts credentials at rest with that key, so an export from one imports
cleanly into the other without ever decrypting the secret:

```bash
# on the machine holding the working credential
docker exec -u node netsec-n8n n8n export:credentials --all --output=/tmp/creds.json
docker cp netsec-n8n:/tmp/creds.json ./creds.json

# on the VM
docker cp ./creds.json netsec-n8n:/tmp/creds.json
docker exec -u node netsec-n8n n8n import:credentials --input=/tmp/creds.json
```

Delete the intermediate `creds.json` afterwards. It is encrypted, not
plaintext, but it is still a credential file sitting on disk.

**If `N8N_ENCRYPTION_KEY` differs between the two instances, the import
succeeds and the credential is unusable.** n8n does not warn about this.

---

## The local stack is retired

The cloud VM is the only place the automation runs. The local Docker
Desktop stack is no longer part of the project, and the dashboard no
longer probes or writes to it.

If you do bring a second instance up somewhere, understand what is and is
not shared:

- Each instance has its own `n8n_data` volume, so accounts, workflows and
  credentials are independent.
- Each polls a *different* `incoming/` directory, so no PCAP is analysed
  twice and no duplicate email is sent.
- They *do* share the Groq API key, and therefore the free-tier limit of
  12,000 tokens per minute. Two concurrent analyses can trigger a 429.
- They share the destination mailbox.

---

## The dashboard button uploads to the VM

The dashboard runs on your machine, but it no longer needs a local Docker
daemon for anything. The **Send S1 / S2 to n8n Alert** button uploads the
session's PCAP over Tailscale straight into the VM's `incoming/`, using
the `scp` binary that ships with Windows and every Unix.

Four environment variables control the target. The defaults match the
deployment described here, so nothing needs to be set for normal use:

| variable | default |
|---|---|
| `NETSEC_REMOTE_HOST` | `100.68.246.54` |
| `NETSEC_REMOTE_USER` | `ubuntu` |
| `NETSEC_REMOTE_INCOMING` | `/home/ubuntu/netsec/incoming` |
| `NETSEC_SSH_KEY` | `~/.ssh/netsec-agent.key/ssh-key-2026-07-12.key` |

Before uploading, the button probes `judge_api` and n8n on the remote
host. If Tailscale is disconnected it says so and refuses to upload,
rather than reporting a success that goes nowhere.

Dropping a file on the VM by hand does the same thing:

```bash
scp -i <key> capture.pcap ubuntu@82.70.253.253:~/netsec/incoming/
```

**Nothing about the analysis runs locally any more.** The pipeline,
the models, and every LLM call happen on the VM. Docker Desktop can stay
closed, or be uninstalled.

---

## Verifying the LLM path, not the cache

`llm_judge/cache/judge_cache.sqlite` is keyed by candidate features, not
by PCAP filename. A cache copied over from another machine will answer for
PCAPs that machine never analysed. During this deployment, two consecutive
"successful" test runs returned `cache_hits: 4` and made no API call at
all.

Any test meant to prove the provider works must move the cache aside
first:

```bash
mv ~/netsec/llm_judge/cache/judge_cache.sqlite /tmp/
curl -s -X POST http://100.68.246.54:8765/analyze \
  -H "Content-Type: application/json" \
  -d '{"pcap_path":"incoming/dns_amp.pcap","label":"S1"}'
mv /tmp/judge_cache.sqlite ~/netsec/llm_judge/cache/
```

A genuine live run reports `"cache_hits": 0`. This also applies to any
future benchmark of latency, token cost, or judge quality - with the cache
in place you are measuring SQLite.

---

## Troubleshooting

| symptom | cause |
|---|---|
| `address already in use` on `docker compose up` | override file missing the `!override` tag; base `0.0.0.0` binding still active |
| n8n unreachable over Tailscale, SSH fine | `tailscale0` ACCEPT rule missing or lost after reboot (`netfilter-persistent save` not run) |
| `NOT NULL constraint failed: workflow_entity.id` | workflow JSON has no `id`; stamp one on a copy |
| Credential imports but the node still errors | `N8N_ENCRYPTION_KEY` differs between source and target |
| Verdicts return instantly with `cache_hits` > 0 | copied `judge_cache.sqlite`; move it aside |
| Basic auth prompt never appears | expected - modern n8n uses owner accounts, not `N8N_BASIC_AUTH_*` |
