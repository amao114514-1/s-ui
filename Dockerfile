FROM --platform=$BUILDPLATFORM node:24-alpine AS front-builder
WORKDIR /app
COPY frontend/ ./
RUN npm ci && npm run build

FROM golang:1.26-alpine AS backend-builder
WORKDIR /app
ARG TARGETARCH
ARG TARGETVARIANT
ARG CRONET_VERSION
ARG CRONET_SHA256
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"
ENV GOARCH=$TARGETARCH

RUN apk upgrade --no-cache --scripts=no apk-tools && \
    apk add --no-cache \
    gcc \
    musl-dev \
    libc-dev \
    make \
    git \
    wget \
    unzip \
    bash \
    curl

ENV CC=gcc

RUN test -n "$CRONET_VERSION" && test -n "$CRONET_SHA256" && \
    CRONET_ARCH="$TARGETARCH" && \
    CRONET_URL="https://github.com/SagerNet/cronet-go/releases/download/${CRONET_VERSION}/libcronet-linux-${CRONET_ARCH}.so"; \
    echo "Downloading $CRONET_URL" && \
    wget -q -O ./libcronet.so "$CRONET_URL" && \
    echo "${CRONET_SHA256}  ./libcronet.so" | sha256sum -c - && \
    chmod 755 ./libcronet.so

COPY . .
COPY --from=front-builder /app/dist/ /app/web/html/

RUN if [ "$TARGETARCH" = "arm" ]; then export GOARM=7; [ "$TARGETVARIANT" = "v6" ] && export GOARM=6; fi; \
    go build -ldflags="-w -s" \
    -tags "with_quic,with_grpc,with_utls,with_acme,with_gvisor,with_naive_outbound,with_purego,with_tailscale" \
    -o sui main.go

FROM alpine:3.23
LABEL org.opencontainers.image.authors="alireza7@gmail.com"
ENV TZ=Asia/Tehran
WORKDIR /app
RUN set -ex && apk upgrade --no-cache --scripts=no apk-tools && \
    apk add --no-cache --upgrade bash ca-certificates nftables && \
    addgroup -S s-ui && adduser -S -G s-ui -h /app -s /sbin/nologin s-ui && \
    mkdir -p /app/db /app/cert /app/bin && chown -R s-ui:s-ui /app
COPY --from=backend-builder /app/sui /app/libcronet.so /app/
COPY entrypoint.sh /app/
USER s-ui
ENTRYPOINT [ "./entrypoint.sh" ]
