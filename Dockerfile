# syntax=docker/dockerfile:1.7
# KidGuard API image for Hetzner (or any Docker host). Multi-stage: build with dev deps,
# ship only production deps + compiled JS, run as an unprivileged user.

FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY prisma ./prisma
RUN npx prisma generate
COPY tsconfig.json ./
COPY src ./src
COPY scripts/bootstrap-admin.ts ./scripts/bootstrap-admin.ts
RUN npm run build  && npx tsc scripts/bootstrap-admin.ts --outDir dist-scripts --module commonjs --target ES2022 --esModuleInterop --skipLibCheck  && npm prune --omit=dev \
 && npm install --no-save --omit=dev "prisma@$(node -p "require('./package.json').devDependencies.prisma")"

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    PORT=8080 \
    NODE_OPTIONS="--enable-source-maps --max-old-space-size=512"
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates tini curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/dist-scripts ./dist-scripts
COPY --from=build --chown=node:node /app/prisma ./prisma
COPY --chown=node:node package.json ./
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health/ready || exit 1
# Apply pending migrations, then start. tini forwards SIGTERM for graceful shutdown.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "node node_modules/prisma/build/index.js migrate deploy && exec node dist/server.js"]
