#!/usr/bin/env bash

docker build -t seshador-build .

rm -fr wasm
mkdir wasm
touch wasm/placeholder

docker run -it --rm -v "$PWD:/app" seshador-dev sh -c 'fyne package -os web --source-dir ./cmd/ui --release'
make build-all
