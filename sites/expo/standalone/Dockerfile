FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS builder
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN corepack pnpm install --frozen-lockfile
COPY . .
RUN corepack pnpm build:standalone

FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production PORT=3100 EXPO_DATA_PATH=/data/interest.sqlite
COPY --from=builder /app/dist-standalone ./dist-standalone
COPY standalone/server.mjs ./standalone/server.mjs
COPY lib/interest-validation.ts ./lib/interest-validation.ts
RUN mkdir /data && chown node:node /data
USER node
EXPOSE 3100
CMD ["node", "standalone/server.mjs"]
