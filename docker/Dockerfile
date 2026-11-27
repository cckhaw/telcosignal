FROM node:22.23.5-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=65532:65532 /app/node_modules ./node_modules
COPY --from=build --chown=65532:65532 /app/dist/src ./dist
COPY --from=build /app/package.json ./
USER 65532:65532
HEALTHCHECK NONE
CMD ["dist/common/banner.js"]
