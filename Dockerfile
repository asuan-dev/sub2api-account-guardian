FROM docker.m.daocloud.io/library/golang:1.26.2-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sub2api-guardian ./cmd/guardian

FROM docker.m.daocloud.io/library/alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/sub2api-guardian /app/sub2api-guardian
ENTRYPOINT ["/app/sub2api-guardian"]
