FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS dashboard
WORKDIR /build/apps/dashboard
COPY apps/dashboard/package*.json ./
RUN npm ci
COPY apps/dashboard/ ./
RUN npm run build

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/app/.venv/bin:$PATH \
    PATCHWORK_HOST=0.0.0.0 \
    PATCHWORK_PORT=8000 \
    PATCHWORK_WORKSPACE_ROOT=/workspace \
    PATCHWORK_DASHBOARD_DIST=/app/apps/dashboard/dist

RUN useradd --create-home --uid 10001 patchwork
WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir uv==0.11.28 && \
    uv sync --frozen --no-dev --no-editable

COPY --from=dashboard /build/apps/dashboard/dist ./apps/dashboard/dist

USER patchwork
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).close()"]
CMD ["patchwork-api"]
