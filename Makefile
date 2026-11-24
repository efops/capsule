PREFIX ?= /usr/local
BIN    := bin/capsule

.PHONY: build linux install test clean

build: ## build for this machine
	CGO_ENABLED=0 go build -o $(BIN) .

linux: ## build static Linux binaries for arm64 and amd64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/capsule-linux-arm64 .
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/capsule-linux-amd64 .

install: ## install $(BIN) on this Linux host; run as root. For a cross-built binary: make install BIN=bin/capsule-linux-amd64
	sh dist/install.sh $(BIN)

test: ## unit tests, then every suite against the installed binary; needs Linux, root, busybox-static, nftables, python3, and this user in the capsule group
	go test .
	sudo sh test/smoke.sh $(PREFIX)/bin/capsule
	CAPSULE_HELPER=off sh test/smoke.sh $(PREFIX)/bin/capsule
	sudo sh test/mesh.sh $(PREFIX)/bin/capsule
	CAPSULE_HELPER=off sh test/mesh.sh $(PREFIX)/bin/capsule
	sg capsule -c "sh test/mesh.sh $(PREFIX)/bin/capsule"
	cd test/sock && CGO_ENABLED=0 go build -o ../../bin/sock .
	sudo sh test/cell.sh $(PREFIX)/bin/capsule bin/sock
	CAPSULE_HELPER=off sh test/cell.sh $(PREFIX)/bin/capsule bin/sock
	sg capsule -c "sh test/cell.sh $(PREFIX)/bin/capsule bin/sock"
	sudo sh test/order.sh $(PREFIX)/bin/capsule
	sh test/order.sh $(PREFIX)/bin/capsule
	sg capsule -c "sh test/helper.sh $(PREFIX)/bin/capsule"
	sudo sh test/e2e.sh $(PREFIX)/bin/capsule
	sudo sh test/scale.sh $(PREFIX)/bin/capsule
	sudo sh test/guide.sh $(PREFIX)/bin/capsule

clean:
	rm -rf bin
