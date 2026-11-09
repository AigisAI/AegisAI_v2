FROM node:22-alpine AS builder
RUN apk add --no-cache openssl
RUN corepack enable
WORKDIR /app
COPY . .
RUN corepack pnpm install --frozen-lockfile
RUN corepack pnpm --filter @aegisai/api prisma:generate
RUN corepack pnpm --filter @aegisai/shared build
RUN corepack pnpm --filter @aegisai/api build

FROM node:22-alpine AS runner
RUN apk add --no-cache openssl
RUN corepack enable
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=builder /app/tsconfig.base.json ./tsconfig.base.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/apps/api ./apps/api
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health >/dev/null || exit 1
CMD ["node", "apps/api/dist/main.js"]
