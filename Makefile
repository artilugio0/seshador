build:
	go build ${BUILDFLAGS} -o seshador ./cmd/seshador

build-all:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -o dist/seshador-linux-amd64 ./cmd/seshador
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ${BUILDFLAGS} -o dist/seshador-linux-arm64 ./cmd/seshador
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build ${BUILDFLAGS} -o dist/seshador-darwin-amd64 ./cmd/seshador
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ${BUILDFLAGS} -o dist/seshador-darwin-arm64 ./cmd/seshador
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ${BUILDFLAGS} -o dist/seshador-windows-amd64.exe ./cmd/seshador
	# Optional: tar/zip
	for f in dist/seshador-*; do tar -czf $$f.tar.gz -C dist $$(basename $$f); done
	zip -j dist/seshador-windows-amd64.zip dist/seshador-windows-amd64.exe
