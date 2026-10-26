# GhostWires Mk.IV — production image (BYOK: ships with NO API keys)
# Author: Yasin Mohammed Miah, Student of BCU, BSc Computing Top-Up (Hons)

# ---- build stage
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build && npm prune --omit=dev

# ---- runtime stage
FROM node:22-alpine
LABEL org.opencontainers.image.source="https://github.com/ymmiah/GhostWires" \
      org.opencontainers.image.title="GhostWires Mk.IV" \
      org.opencontainers.image.description="Passive OSINT reconnaissance with bring-your-own-key AI (NVIDIA NIM, Gemini, OpenRouter, Groq)" \
      org.opencontainers.image.authors="Yasin Mohammed Miah"
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    GHOSTWIRES_BYOK_ONLY=1
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/dist-server ./dist-server
# Defence in depth: make sure no .env ever ends up in the image.
RUN rm -f .env .env.* || true
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/api/health" >/dev/null || exit 1
CMD ["node", "dist-server/server.cjs"]
