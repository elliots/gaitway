FROM golang:1.26.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/gaitway ./cmd/gaitway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home gaitway \
    && install -d -o gaitway -g gaitway /var/lib/gaitway
COPY --from=build /out/gaitway /usr/local/bin/gaitway
USER 10001
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/gaitway"]
