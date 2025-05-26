FROM golang:1.24.3-bookworm

RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY . .

# to analize: -gcflags="-m=2"
RUN rm -rf build/liblightergo/ && mkdir -p build/liblightergo/amd64/ && mkdir -p build/liblightergo/arm64/ && \
  	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-archive -trimpath -o ./build/liblightergo/amd64/liblightergo.a ./liblightergo/liblightergo.go && \
    CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -buildmode=c-archive -trimpath -o ./build/liblightergo/arm64/liblightergo.a ./liblightergo/liblightergo.go
