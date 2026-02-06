FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/xip ./cmd/xip

FROM alpine:3.21
RUN adduser -D -H -s /sbin/nologin xip
COPY --from=build /out/xip /usr/local/bin/xip
USER root
EXPOSE 53/tcp 53/udp 80/tcp 443/tcp
ENTRYPOINT ["/usr/local/bin/xip"]
