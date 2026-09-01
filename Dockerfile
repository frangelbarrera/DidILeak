# Self-hosted DidILeak dashboard.
# Build:  docker build -t didileak .
# Run:    docker run -p 3000:3000 didileak
#
# Includes both the Python CLI (so the API route can shell out to it) and the
# Next.js dashboard. The build fails loudly if the dashboard does not compile;
# a broken build must never produce a shippable image.
#
# Optional runtime configuration:
#   DIDILEAK_API_TOKEN        bearer token required on /api/scan. Required
#                            unless DIDILEAK_ALLOW_ANONYMOUS is set.
#   DIDILEAK_ALLOW_ANONYMOUS  "true" serves /api/scan without a token
#                            (local / single-user self-hosting only).
#   DIDILEAK_TRUST_PROXY      "true" behind a reverse proxy that appends the
#                            client IP to x-forwarded-for (rate limiting
#                            then keys on that header).
#   DIDILEAK_MAX_UPLOAD_BYTES max upload size (default 20 MB)

# ---- Stage 1: Python CLI ----------------------------------------------------
FROM python:3.12-slim AS python-stage
WORKDIR /app
COPY pyproject.toml README.md ./
COPY didileak ./didileak
# Runtime dependencies only: no dev toolchain (pytest/ruff/twine) ends up in
# the final image. Non-editable install so site-packages is self-contained.
RUN pip install --no-cache-dir .

# ---- Stage 2: dashboard build ------------------------------------------------
FROM node:22-slim AS node-build
WORKDIR /app/dashboard
# Lockfile first for layer caching and reproducible installs.
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard ./
# No `|| true`: a failing build must fail the image build.
RUN npm run build

# ---- Stage 3: runtime ---------------------------------------------------------
# python:3.12-slim keeps the same interpreter the CLI was installed for (its
# `#!/usr/local/bin/python` shebang and 3.12 site-packages both work as built).
FROM python:3.12-slim AS runtime
# Node runtime from the official image (same Debian base); running `node`
# directly as PID 1 gives clean SIGTERM handling without an npm wrapper.
COPY --from=node:22-slim /usr/local/bin/node /usr/local/bin/node
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 didileak

COPY --from=python-stage --chown=didileak:didileak \
    /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-stage --chown=didileak:didileak \
    /usr/local/bin/didileak /usr/local/bin/didileak
COPY --from=node-build --chown=didileak:didileak /app/dashboard /app/dashboard

WORKDIR /app/dashboard
ENV NODE_ENV=production
ENV PATH="/usr/local/bin:${PATH}"
USER didileak
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000"]
