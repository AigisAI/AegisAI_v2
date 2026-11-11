FROM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS builder
RUN corepack enable
WORKDIR /app
COPY . .
RUN corepack pnpm install --frozen-lockfile
RUN corepack pnpm --filter @aegisai/shared build
RUN corepack pnpm --filter @aegisai/private-web build

FROM nginx:stable-alpine3.24-slim@sha256:e2355aa95529a7999dad94ddcb45a8768abf6fb0b204c93b1a3ffce477d7b893
LABEL org.aegisai.runtime-profile="private-single-host-v1"
COPY apps/private-web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/private-web/dist /usr/share/nginx/html
EXPOSE 80
