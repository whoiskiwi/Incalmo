# ============================================================
# Attacker workstation for the SEGMENTED Equifax range (PLAN 附录 C).
# ------------------------------------------------------------
# Why this exists: once `intnet` is `internal: true`, the database can no longer
# reach the Mac host, so the Mac can no longer be the attacker. The attacker must
# be a real box ON extnet (10.0.0.50). This container runs the Incalmo strategy
# and the ExfilReceiver; the Incalmo source is bind-mounted (see compose), so you
# edit on the Mac and it is live in here.
# ============================================================
FROM python:3.12-slim

# Attacker tooling for the EARLY segmented steps (C.5.1 reachability + scan):
#   nmap            -> ScanAgent
#   openssh-client  -> lateral move (later: via webserver as a jump host)
#   curl            -> exfil relay smoke-test
#   iputils-ping    -> C.5.1 acceptance test (can reach web, cannot reach db)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap openssh-client curl ca-certificates iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Third-party Python deps. The incalmo/ package itself is bind-mounted at runtime
# (not installed), so we only install its dependencies here.
# Only what the deterministic baseline needs for now; langchain is added in
# stage 4 (LLM planner). Keep in sync with pyproject.toml [dependencies].
RUN pip install --no-cache-dir "pydantic>=2.7" "python-dotenv>=1.0"
# TODO(stage 4): RUN pip install --no-cache-dir "langchain>=0.3" "langchain-anthropic>=0.3"

# Code lives here via a bind mount (see docker-compose.segmented.yml). Running
# `python -m incalmo.core.strategy.equifax_baseline` from this dir finds the
# incalmo package, and ExfilReceiver(output_dir="output") writes to ./output.
WORKDIR /incalmo

# TODO(you, C.5.4): when WebShell/SshRunner are reworked to be network-native
# (attack webserver over 10.0.0.2 instead of shelling out to `docker run`), this
# image will also need metasploit-framework (heavy ~2GB) and the stolen ssh key.
# Left out for now so the C.5.1 image stays small.

# No long-running service: stay parked; `docker compose exec attacker bash` to use it.
CMD ["sleep", "infinity"]
