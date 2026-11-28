FROM node:26.13.0-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68 AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY mock ./mock
RUN npm run build && npm prune --omit=dev

FROM node:26.13.0-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68 AS base
# Debian security updates applied at build so fixed OS packages (e.g. libssl3) are picked up
# before the upstream base image is rebuilt. Revisit distroless when its base is patched (R-007).
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn*
# npm/npx/corepack removed: not needed at runtime, reduces attack surface and scanner noise
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/package.json ./
USER node

# Synthetic mock telcos (sandbox only). Never deployed alongside real telco connectivity.
FROM base AS mock
COPY --from=build --chown=node:node /app/dist/mock ./dist/mock
CMD ["node", "dist/mock/run-mocks.js"]

# Platform runtime (default target).
FROM base AS runtime
COPY --from=build --chown=node:node /app/dist/src ./dist
CMD ["node", "dist/main.js"]
