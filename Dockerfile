# Build the browser bundle in a pinned stage so npm and its dependency graph
# never enter the runtime image.
FROM docker.io/library/node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
# The tag and digest select Node, while these checks also prove the npm bundled
# by that image matches the separately reviewed package-manager pin.
RUN test "$(node --version)" = "v24.22.1" && \
    test "$(npm --version)" = "11.19.1" && \
    npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
# The frontend suite reads the theme catalog from the Go source that defines
# it, because internal/theme is what the origin actually stamps and deriving
# the catalog from the stylesheet or the switcher instead let an unvalidated
# theme ship. That anchor has to exist in THIS stage too: the frontend job in
# CI has the whole checkout, but this stage deliberately does not, so without
# this line the container build fails on a file the test correctly demands.
COPY internal/theme/types.go /src/internal/theme/types.go
RUN npm run check && npm test && npm run build

# Compile and test a static Go binary for both amd64 CI and arm64 production;
# Buildx selects the matching architecture from this manifest-list pin.
FROM docker.io/library/golang:1.26.10-trixie@sha256:909771fef53e3dcb0950255f0c9a8b4728c3b841e61509c7b29b098de7ee02d4 AS backend
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=frontend /src/internal/web/dist/ ./internal/web/dist/
RUN go test ./... && \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/lidersea-com ./cmd/server

# The final shell-less, non-root image contains only the independently
# promotable site binary and no compilers, package managers, or source tree.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
COPY --from=backend --chown=65532:65532 /out/lidersea-com /lidersea-com
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/lidersea-com"]
