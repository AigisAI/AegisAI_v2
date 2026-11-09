FROM node:22-alpine AS builder
ARG VITE_PRODUCTION_RUNTIME=false
ENV VITE_PRODUCTION_RUNTIME=${VITE_PRODUCTION_RUNTIME}
RUN corepack enable
WORKDIR /app
COPY . .
RUN corepack pnpm install --frozen-lockfile
RUN corepack pnpm --filter @aegisai/shared build
RUN corepack pnpm --filter @aegisai/web build

FROM nginx:1.27-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
