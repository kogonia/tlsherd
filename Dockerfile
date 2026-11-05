# Multi-stage build for tlsherd-server (and optional CLI tools).
# Build from the repository root:
#   docker build -t tlsherd-server:local .
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tlsherd-server ./cmd/tlsherd-server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/tlsherd-server /tlsherd-server
USER nonroot:nonroot
EXPOSE 8443 8444
ENTRYPOINT ["/tlsherd-server"]
