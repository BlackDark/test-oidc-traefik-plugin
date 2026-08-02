FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /repo
COPY . .
WORKDIR /repo/cmd/extauth-server
RUN --mount=type=cache,target=/go/pkg/mod go mod download
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/amd64/extauth-server . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o /out/arm64/extauth-server .

FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETARCH
COPY --from=build /out/${TARGETARCH}/extauth-server /extauth-server
USER nonroot:nonroot
ENTRYPOINT ["/extauth-server"]
