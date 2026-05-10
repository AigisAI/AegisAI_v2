FROM node:20-bookworm-slim AS builder
RUN corepack enable
WORKDIR /app
COPY . .
RUN corepack pnpm install --frozen-lockfile
RUN corepack pnpm --filter @aegisai/ai build

FROM node:20-bookworm-slim AS runner
RUN corepack enable
WORKDIR /app
ENV NODE_ENV=production
ENV AI_PORT=8000
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/apps/ai ./apps/ai
EXPOSE 8000
CMD ["node", "apps/ai/dist/src/server.js"]
