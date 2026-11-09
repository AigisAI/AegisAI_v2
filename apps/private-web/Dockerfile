FROM node:22-alpine AS builder
RUN corepack enable
WORKDIR /app
COPY . .
RUN corepack pnpm install --frozen-lockfile
RUN corepack pnpm --filter @aegisai/shared build
RUN corepack pnpm --filter @aegisai/private-web build

FROM nginx:1.27-alpine
LABEL org.aegisai.runtime-profile="private-single-host-v1"
COPY apps/private-web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/private-web/dist /usr/share/nginx/html
EXPOSE 80
