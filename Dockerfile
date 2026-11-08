FROM oven/bun:1.4.4 AS web
# Bun only: remove the image's `node` -> bun fallback so nothing named node
# exists. Every script runs with `bun --bun`.
RUN rm -rf /usr/local/bun-node-fallback-bin
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
# Type-checks (scripts/vue-tsc.ts) and bundles on the Bun runtime; no Node.
RUN mkdir -p /internal/dashboard/dist && bun run build
# Persona page script (behavior signals and session recording).
WORKDIR /site
COPY site/package.json site/bun.lock ./
RUN bun install --frozen-lockfile
COPY site/ ./
RUN mkdir -p /adapters/demogpu/static/assets && bun run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /internal/dashboard/dist ./internal/dashboard/dist
COPY --from=web /adapters/demogpu/static/assets ./adapters/demogpu/static/assets
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agenttrap ./cmd/agenttrap \
 && mkdir -p /out/state/agenttrap /out/bootstrap

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/agenttrap /usr/local/bin/agenttrap
COPY --from=build --chown=65532:65532 /out/state/agenttrap /var/lib/agenttrap
COPY --from=build --chown=65532:65532 /out/bootstrap /bootstrap
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agenttrap"]
