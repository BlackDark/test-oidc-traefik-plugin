FROM golang:1.26-alpine AS build
WORKDIR /repo
COPY . .
WORKDIR /repo/cmd/extauth-server
RUN go mod download
RUN CGO_ENABLED=0 go build -o /out/extauth-server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/extauth-server /extauth-server
USER nonroot:nonroot
ENTRYPOINT ["/extauth-server"]
