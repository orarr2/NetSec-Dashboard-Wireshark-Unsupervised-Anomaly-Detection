# VM Deployment - running the analysis stack 24/7

Running the four-service analysis stack (`deploy/docker-compose.yml`)
on a small VM you own, reachable only over a private Tailscale network.
The reference deployment uses a free Oracle Cloud ARM instance; any
Ubuntu 22.04+ VM with 4 GB RAM works identically. `deploy/README.md`
covers the minimal quickstart; this file goes deeper on ARM64
compatibility, the Tailscale-only network model, first-time setup, and
verifying that the analysis path actually made an LLM call.

> All addresses and key paths in this file are placeholders - substitute
> your own VM's values. Nothing here identifies a live machine.

---

## Why a VM

| | laptop | Always Free VM |
|---|---|---|
| Availability | only while you leave it on | 24/7 |
| Cost | free | free (Always Free tier, no card charge) |
| RAM available to the stack | shared with everything else | 24 GB dedicated (ARM tier) |
| Cores | shared | 4 dedicated |

The practical difference: a PCAP uploaded at 3 am gets analysed at 3 am.
Session history, per-device baselines, beaconing over days - all of it
becomes meaningful only once the analysis machine is always on.

---

## The reference machine (Oracle Always Free ARM)

| property | value |
|---|---|
| Shape | `VM.Standard.A1.Flex` |
| Resources | 4 OCPU / 24 GB RAM / 100 GB boot volume |
| OS | Ubuntu 22.04 or 24.04 LTS, **aarch64** |
| Public IP | `<vm-public-ip>` (SSH only) |
| Tailscale IP | `<vm-tailscale-ip>` (everything else) |
| Project path | `<repo>/deploy` |
| Data root | `/srv/netsec` |

`VM.Standard.A1.Flex` at 4 OCPU / 24 GB consumes the entire Always Free
ARM allowance for the tenancy (3 000 OCPU-hours and 18 000 GB-hours per
month). A second A1 instance cannot be created alongside it.

**Staying $0.** Free-tier limits Oracle actually enforces: block
storage total ≤ 200 GB (a second A1 instance is also blocked). Keep the
100 GB boot volume; do not add a block volume that pushes past 200 GB.
The `retention` service keeps `/srv/netsec` bounded, so the disk never
spills onto a paid resource.

Any other provider (AWS, Azure, Hetzner, a self-hosted Pi 5, a home
NAS) works the same way once Docker + Tailscale + chrony are installed.

SSH in with:

```bash
ssh -i <path-to-your-ssh-key> ubuntu@<vm-public-ip>
```

---

## ARM64 compatibility

The Always Free VM is aarch64, not x86-64. The main risk going in was
that `worker` and `ingest_api` install the project's `requirements.txt`
inside the image, and a missing wheel means compiling numerical
libraries from source (slow and RAM-hungry on 4 cores).

It is a non-issue. Every pinned dependency publishes a manylinux
aarch64 wheel:

| package | wheel |
|---|---|
| `numpy==2.4.6` | `manylinux_2_27_aarch64` |
| `pandas==3.0.3` | `manylinux_2_24_aarch64` |
| `scikit-learn==1.9.0` | `manylinux_2_27_aarch64` |
| `scipy==1.17.1` | `manylinux_2_27_aarch64` |
| `torch==2.12.1` | `manylinux_2_28_aarch64` |
| `fastapi==0.115.6` / `uvicorn==0.32.1` / `httpx==0.28.1` | pure-python |

Only `manuf==1.1.5` is source-only, and it is pure Python that builds
in seconds against the `gcc` already present in the builder image.
WeasyPrint (installed inside `Dockerfile.worker`) has pre-built
aarch64 wheels via `libpango`/`libcairo` apt packages the Dockerfile
pulls in.

To re-check this after a dependency bump, without installing anything:

```bash
docker run --rm -v $PWD/requirements.txt:/req.txt python:3.11-slim \
  bash -c "pip install --dry-run --only-binary=:all: -r /req.txt"
```

`n8nio/n8n:latest` publishes a native arm64 image, so it needs no
special handling either.

---

## Network model: Tailscale only

None of the four services is exposed to the internet. The only port
reachable on the public IP is 22.

```
your laptop  ──(Tailscale, WireGuard)──►  vm
<laptop-tailscale-ip>                     <vm-tailscale-ip>:5678  n8n
                                          <vm-tailscale-ip>:8766  ingest_api

the internet ────────────────────────►    <vm-public-ip>:22    SSH only
                                          <vm-public-ip>:5678  no listener
                                          <vm-public-ip>:8766  no listener
```

`worker` and `retention` publish no ports at all - they consume the
DB queue and the filesystem.

Three things are required to make this hold, and missing any one of
them silently breaks it.

### 1. Bind the published ports to the Tailscale IP

`deploy/docker-compose.yml` already binds every port to `${TS_BIND}`:

```yaml
services:
  n8n:
    ports:
      - "${TS_BIND:-127.0.0.1}:5678:5678"
  ingest_api:
    ports:
      - "${TS_BIND:-127.0.0.1}:8766:8766"
```

Set `TS_BIND` in `deploy/.env` to the VM's Tailscale IP. The loopback
default is intentional - a mis-configured `.env` fails closed, binding
only to `127.0.0.1` rather than everywhere.

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

UDP 41641 lets Tailscale establish a direct peer connection. Without
it the tunnel still works, but every packet is relayed through a DERP
server - correct behaviour, higher latency.

Note that `-I INPUT 5` is fragile: the exact position depends on how
many rules the image already ships. Verify the resulting chain with
`sudo iptables -L INPUT --line-numbers` and adjust the position so the
ACCEPTs sit *before* the trailing REJECT.

### 3. Leave the Oracle Security List alone

The VCN's default security list allows only ingress on 22. Do not open
5678 or 8766 there. Docker's published ports bypass the INPUT chain
via DNAT, so the cloud-level rule is the backstop that matters if the
bind in step 1 is ever wrong.

Verify both directions after any change:

```bash
# Tailscale IP - answers
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-tailscale-ip>:5678/
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-tailscale-ip>:8766/healthz

# Public IP - MUST be blank / connection refused / timeout
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-public-ip>:5678/
curl -s -o /dev/null -w "%{http_code}\n" http://<vm-public-ip>:8766/healthz
```

The public-IP curl should print `000` (no answer). If it returns any
HTTP code, revisit step 1.

---

## Deploying from scratch

Assuming a fresh Always Free ARM instance running Ubuntu 22.04+.

### 1. Docker

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
sudo systemctl enable --now docker
```

`systemctl enable` plus the `restart: unless-stopped` set on every
service in `deploy/docker-compose.yml` means the stack returns on its
own after a reboot. There is nothing extra to run at boot.

There is one race worth noting: `${TS_BIND}` is a `tailscale0` address,
so Docker can start before `tailscaled` assigns the IP and fail to
bind. `restart: unless-stopped` retries with backoff, so it converges;
add an `After=tailscaled.service` docker.service drop-in if the delay
matters:

```bash
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/tailscale.conf <<'EOF'
[Unit]
After=tailscaled.service
Requires=tailscaled.service
EOF
sudo systemctl daemon-reload
```

### 2. Tailscale + chrony

```bash
curl -fsSL https://tailscale.com/install.sh | sudo sh
sudo tailscale up --hostname=<vm-hostname>
sudo apt-get install -y chrony        # NTP - needed for HMAC anti-replay
```

Then apply the firewall rules from the section above.

### 3. The project

Clone the fork (the entire deployment ships in the repo now - nothing
extra to copy across):

```bash
git clone <your-fork>
cd <repo>/deploy
cp .env.example .env
# Edit .env - at minimum TS_BIND (your Tailscale IP) and
# N8N_ENCRYPTION_KEY. Every other variable ships with a working
# default from the code.
```

Prepare the data root once:

```bash
sudo mkdir -p /srv/netsec
sudo chown $USER /srv/netsec
```

### 4. Bring it up

```bash
docker compose up -d
```

First start takes 2-6 min while Docker builds the `ingest_api` and
`worker` images and pulls `n8nio/n8n:latest`. Subsequent restarts are
seconds. Confirm with:

```bash
docker compose ps            # four services Up
curl -s http://<vm-tailscale-ip>:8766/healthz   # {"status":"ok","schema":<n>}
```

### 5. Register a sensor

Every uploader needs its own HMAC secret. `deploy/create_sensor.py`
writes into the DB the containers created, so run it under the same
user that owns `/srv/netsec` (or via `sudo` with the same
`NETSEC_DATA_ROOT`):

```bash
# From deploy/
sudo NETSEC_DATA_ROOT=/srv/netsec python3 create_sensor.py laptop
# From the repo root, the same helper is:
sudo NETSEC_DATA_ROOT=/srv/netsec python3 deploy/create_sensor.py laptop
```

Copy the three printed lines
(`NETSEC_SENSOR_ID`, `NETSEC_SENSOR_SECRET`, `NETSEC_API_TOKEN`) into
the environment of whatever machine will upload.

Cross-sensor authorisation is enforced: a bearer token can read only
its own sessions and reports. Set `NETSEC_ADMIN_SENSOR=<name>` if you
want one sensor's token to read every sensor's sessions (typical for a
central-dashboard account).

---

## Importing the n8n alert workflow

Two paths, both working. The template ships as a mounted volume at
`/workflows` inside the n8n container, so the CLI import needs no file
copy:

```bash
docker compose exec n8n n8n import:workflow \
  --input=/workflows/mvp_triage_email.json
docker compose exec n8n n8n list:workflow
```

Or through the UI: open `http://<vm-tailscale-ip>:5678/`, create the
owner account (the first visit prompts for it - keep that credential
safe; `N8N_BASIC_AUTH_*` is not supported in modern n8n), then
**Workflows** → **⋮** → **Import from File** →
`deploy/n8n_workflows/mvp_triage_email.json`.

The workflow imports **inactive**. Open it, click the **Send Email
Alert** node, attach an SMTP credential (see the next section), set
the from/to addresses, then toggle **Active** (top-right).

Copy the **Production URL** of the *Worker Webhook* node
(`http://<vm-ip>:5678/webhook/netsec-alert`) into `N8N_WEBHOOK_URL` in
`deploy/.env`, then `docker compose restart worker`.

---

## Credentials

Modern n8n releases ignore `N8N_BASIC_AUTH_ACTIVE` and friends. The
first visit to `http://<vm-tailscale-ip>:5678` prompts for an owner
account instead. Create it there; the env vars in the compose file
have no effect.

The SMTP credential can be re-entered by hand
(see `AUTOMATION_QUICKSTART.md` for the field values), or migrated
from an existing n8n instance. Migration only works because both
instances read the same `N8N_ENCRYPTION_KEY` from the same copied
`.env` - n8n encrypts credentials at rest with that key, so an export
from one imports cleanly into the other without ever decrypting the
secret:

```bash
# on the source instance
docker compose exec n8n \
  n8n export:credentials --all --output=/tmp/creds.json
docker compose cp n8n:/tmp/creds.json ./creds.json

# on the destination
docker compose cp ./creds.json n8n:/tmp/creds.json
docker compose exec n8n \
  n8n import:credentials --input=/tmp/creds.json
```

Delete the intermediate `creds.json` afterwards. It is encrypted, not
plaintext, but it is still a credential file sitting on disk.

**If `N8N_ENCRYPTION_KEY` differs between the two instances, the
import succeeds and the credential is unusable.** n8n does not warn
about this.

---

## The dashboard button uploads to the VM

The dashboard runs on your machine, but it no longer needs a local
Docker daemon for anything. The **Send S1 / S2 to n8n Alert** button
uploads the session's PCAP over Tailscale using the `scp` binary that
ships with Windows and every Unix.

Four environment variables control the target. **All ship blank** by
default; the button reports "set NETSEC_REMOTE_HOST" until they are
configured, so a fresh fork cannot silently upload to somebody else's
VM (`deploy/.env.example` documents them):

| variable | example value |
|---|---|
| `NETSEC_REMOTE_HOST` | `<vm-tailscale-ip>` |
| `NETSEC_REMOTE_USER` | `ubuntu` |
| `NETSEC_REMOTE_INCOMING` | `/srv/netsec/incoming` (or wherever your intake watches) |
| `NETSEC_SSH_KEY` | `<path-to-your-ssh-key>` |

Before uploading, the button probes `judge_api` (`:8765`) and n8n
(`:5678`) on the remote host. If Tailscale is disconnected, or those
services aren't listening, it says so and refuses to upload rather
than reporting a success that goes nowhere.

Dropping a file on the VM by hand does the same thing:

```bash
scp -i <key> capture.pcap ubuntu@<vm-public-ip>:/srv/netsec/incoming/
```

The **first-class** upload path (documented in
`AUTOMATION_QUICKSTART.md`) is the ingest API - HMAC-signed,
streaming, no size cap, auto-analysed on arrival:

```bash
python3 tools/upload_pcap.py capture.pcapng
```

The scp path exists because it works on every OS with no dependencies
beyond ssh, and because it maps cleanly to the local-desktop era. The
HTTP path is what the sensor agent uses in production.

**Nothing about the analysis runs locally any more** on the button
path. The pipeline, the models, and every LLM call happen on the VM.
Docker Desktop can stay closed, or be uninstalled.

---

## Verifying the LLM path, not the cache

`llm_judge/cache/judge_cache.sqlite` is keyed by candidate features,
prompt version and model id - not by PCAP filename. A cache copied
over from another machine will answer for PCAPs that machine never
analysed. During earlier deployments, two consecutive "successful"
test runs returned `cache_hits: N` and made no API call at all.

Any test meant to prove the provider works must move the cache aside
first:

```bash
mv <repo>/llm_judge/cache/judge_cache.sqlite /tmp/
# Run one PCAP through the CLI (or upload one and read /v1/reports/N.json)
python3 llm_judge/judge_cli.py capture.pcap \
  --output /tmp/verdicts.json --markdown /tmp/verdicts.md
grep '"cache_hits"' /tmp/verdicts.json                 # expect "cache_hits": 0
mv /tmp/judge_cache.sqlite <repo>/llm_judge/cache/
```

A genuine live run reports `"cache_hits": 0`. This also applies to any
future benchmark of latency, token cost or judge quality - with the
cache in place you are measuring SQLite.

The `analyze-pcap.yml` GitHub Actions workflow gets this right for
free: every run starts on a fresh runner with no cache, so its
verdicts (in the auto-opened Issue) are always genuinely live. The
current run of that workflow was verified to record
`cache_hits: 0` for both judges in a two-model Ollama panel.

---

## Troubleshooting

| symptom | cause |
|---|---|
| `address already in use` on `docker compose up` | another process (or an older compose stack) already binds `${TS_BIND}:5678` or `:8766`. `sudo lsof -i :5678` to find it. |
| n8n unreachable over Tailscale, SSH fine | `tailscale0` ACCEPT rule missing or lost after reboot (`netfilter-persistent save` not run) |
| `docker compose up -d` fails only immediately after reboot | `${TS_BIND}` not yet assigned - Tailscale hadn't finished starting. `restart: unless-stopped` covers it; the `After=tailscaled.service` drop-in above avoids the noise. |
| `NOT NULL constraint failed: workflow_entity.id` | using an old n8n version's import; the shipped workflow now includes an explicit `id`. If you edited it, add one. |
| Credential imports but the node still errors | `N8N_ENCRYPTION_KEY` differs between source and target |
| Verdicts return instantly with `cache_hits` > 0 | copied or stale `judge_cache.sqlite`; move it aside |
| Basic auth prompt never appears | expected - modern n8n uses owner accounts, not `N8N_BASIC_AUTH_*` |
| `sqlite3.OperationalError: unable to open database file` from `create_sensor.py` | `db/netsec.db` is owned by the container's user; run with `sudo` and the matching `NETSEC_DATA_ROOT` |
| Reports have no `.pdf` field but `.html` works | WeasyPrint failed to import in the `worker` image; check `docker compose logs worker` for the specific system-library error (`libpango` / `libcairo`) |
