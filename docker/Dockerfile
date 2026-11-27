FROM node:22.23.5-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22.23.5-bookworm-slim
# Debian security updates applied at build so fixed OS packages (e.g. libssl3) are picked up
# before the upstream base image is rebuilt. Revisit distroless when its base is patched (R-007).
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist/src ./dist
COPY --from=build --chown=node:node /app/package.json ./
USER node
CMD ["node", "dist/common/banner.js"]
