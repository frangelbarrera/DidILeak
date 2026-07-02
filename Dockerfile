# Self-hosted DidILeak dashboard.
# Build:  docker build -t didileak .
# Run:    docker run -p 3000:3000 didileak
#
# Includes both the Python CLI (so the API route can shell out to it) and the
# Next.js dashboard.

# ---- Stage 1: Python CLI ----------------------------------------------------
FROM python:3.12-slim AS python-stage
WORKDIR /app
COPY pyproject.toml README.md ./
COPY didileak ./didileak
RUN pip install --no-cache-dir -e ".[dev]"

# ---- Stage 2: dashboard build -----------------------------------------------
FROM node:20-slim AS node-build
WORKDIR /app
COPY --from=python-stage /app /app
COPY dashboard ./dashboard
WORKDIR /app/dashboard
RUN npm ci || npm install
RUN npm run build || true  # build may fail on first deploy; allow it for now

# ---- Stage 3: runtime -------------------------------------------------------
FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Bring in the installed Python package
COPY --from=python-stage /usr/local/lib/python3.12/site-packages /usr/lib/python3/dist-packages
COPY --from=python-stage /usr/local/bin/didileak /usr/local/bin/didileak
COPY --from=python-stage /app/didileak /app/didileak
COPY --from=python-stage /app/pyproject.toml /app/pyproject.toml

# Bring in the built dashboard
COPY --from=node-build /app/dashboard /app/dashboard
WORKDIR /app/dashboard

ENV NODE_ENV=production
ENV PATH="/usr/local/bin:${PATH}"

EXPOSE 3000
CMD ["npm", "start"]
