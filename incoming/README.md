# incoming/ - drop PCAPs here to trigger the autonomous LLM Judge

Any file pushed under this directory whose name ends in `.pcap` or
`.pcapng` triggers `.github/workflows/analyze-pcap.yml`:

1. GitHub spins up an Ubuntu runner (free).
2. Installs `tshark`, the project's Python deps, and Ollama with `llama3.2`
   (cached between runs).
3. Runs `llm_judge/judge_cli.py` on the PCAP - same detection pipeline as
   the dashboard, then the LLM judge with the rule guardrail on.
4. Uploads `verdicts.json` + `verdicts.md` + logs as an artifact.
5. Opens a **GitHub Issue** with the verdict table so you see it on mobile
   without leaving GitHub.

## How to trigger

- **Push a PCAP here** from any machine (`git add`, `git commit`, `git push`).
- Or manually: **Actions → Analyze PCAP (LLM Judge) → Run workflow** - pick a
  file path (defaults to the first file in this folder, else a sample).

## Cost

Ollama runs on the GitHub-hosted runner, so **there is no LLM cost**. Public
repos get unlimited free Actions minutes; private repos have 2,000 free
minutes per month per account.

## Notes

- The runner is stateless per run - no PCAP is retained after the artifact
  window expires.
- Recorded PCAPs pushed here become part of the repo history. If they
  contain sensitive traffic, either `.gitignore` them and only push during
  analysis, or use a private fork.
