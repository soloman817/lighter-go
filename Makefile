build:
	rm -rf ./liblightergo-*.tar.gz && \
		rm -rf ./build/liblightergo/ && \
		mkdir -p ./build/liblightergo/ && \
		docker build -t liblightergo:latest . && \
		docker create --name liblightergo-build liblightergo:latest && \
		docker cp liblightergo-build:/src/build/liblightergo/. ./build/liblightergo && \
		docker rm liblightergo-build && \
		tar -czf liblightergo-`date -u +%y%m%d%H%M`.tar.gz -C build liblightergo

.PHONY: build