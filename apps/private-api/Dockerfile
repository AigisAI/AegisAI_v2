FROM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS builder
RUN apk add --no-cache openssl
RUN corepack enable
WORKDIR /app
COPY . .
RUN corepack pnpm install --frozen-lockfile
RUN corepack pnpm --filter @aegisai/shared build
RUN corepack pnpm --filter @aegisai/private-api build

FROM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS runtime-dependencies
RUN apk add --no-cache openssl
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml .npmrc ./
COPY deploy/aws-ec2/build-workspace.yaml ./pnpm-workspace.yaml
COPY apps/private-api/package.json ./apps/private-api/package.json
COPY packages/shared/package.json ./packages/shared/package.json
COPY packages/private-runtime-db/package.json ./packages/private-runtime-db/package.json
COPY packages/private-runtime-db/prisma ./packages/private-runtime-db/prisma
RUN corepack pnpm install --prod --frozen-lockfile --ignore-scripts
RUN corepack pnpm --filter @aegisai/private-api exec prisma generate --schema ../../packages/private-runtime-db/prisma/schema.prisma

FROM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS runner
RUN apk add --no-cache openssl
RUN corepack enable && corepack prepare pnpm@10.34.9 --activate \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
WORKDIR /app
ENV NODE_ENV=production COREPACK_ENABLE_NETWORK=0
LABEL org.aegisai.runtime-profile="private-single-host-v1"
COPY --from=runtime-dependencies /app/package.json ./package.json
COPY deploy/aws-ec2/container-workspace.yaml ./pnpm-workspace.yaml
COPY --from=builder /app/tsconfig.base.json ./tsconfig.base.json
COPY --from=runtime-dependencies /app/node_modules ./node_modules
COPY --from=runtime-dependencies /app/packages ./packages
COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder /app/packages/private-runtime-db/generated ./packages/private-runtime-db/generated
COPY --from=builder /app/packages/private-runtime-db/prisma ./packages/private-runtime-db/prisma
# Keep the host broker/maintenance ABI, with a distinct workspace package name.
COPY --from=runtime-dependencies /app/apps/private-api ./apps/api
COPY --from=builder /app/apps/private-api/dist ./apps/api/dist
RUN ln -s api /app/apps/private-api
COPY deploy/aws-ec2/runtime-profile.json ./private-runtime-profile.json
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=12 \
  CMD wget -qO- http://127.0.0.1:3000/api/health >/dev/null || exit 1
CMD ["node", "apps/api/dist/main.js"]
