.PHONY: help build build-release build-release-no-api build-release-api-only build-pi-zero-no-api build-pi-zero-api-only release-deb-no-api release-deb-arm64-no-api release-deb-pi-zero-no-api release-deb-api-only release-deb-arm64-api-only release-deb-pi-zero-api-only test-variants test test-integration build-loadtest test-loadtest docker-up docker-down docker-rebuild release-deb release-deb-arm64 build-pi-zero release-deb-pi-zero

help:
	@echo "build                - cargo build (debug, whole workspace)"
	@echo "build-release        - cargo build --release (whole workspace)"
	@echo "build-release-no-api - release build, dashboard only (no /api/v1 JSON API)"
	@echo "build-release-api-only - release build, JSON API only (no dashboard)"
	@echo "build-pi-zero        - cross/cargo build for Raspberry Pi Zero ARMv6 (target arm-unknown-linux-gnueabihf)"
	@echo "build-pi-zero-no-api / build-pi-zero-api-only - the same Pi Zero build, dashboard only / JSON API only"
	@echo "test                 - cargo test (unit tests, whole workspace)"
	@echo "test-variants        - api crate tests for the dashboard-only and API-only builds"
	@echo "test-integration     - Docker-based black-box API/DNS integration suite"
	@echo "build-loadtest       - build the standalone Go DNS load tester in target/dns-loadtest"
	@echo "test-loadtest        - race-checked Go load tester tests and vet (localhost fixtures)"
	@echo "docker-up            - build the image and start the dev container (deploy/docker-compose.yml)"
	@echo "docker-down          - stop and remove the dev container"
	@echo "docker-rebuild       - stop, rebuild the image with --no-cache, and restart the dev container"
	@echo "release-deb          - build the amd64 .deb package (target/dns-deny_*_amd64.deb)"
	@echo "release-deb-arm64    - build the arm64 .deb package (target/dns-deny_*_arm64.deb)"
	@echo "release-deb-pi-zero  - build the Raspberry Pi Zero ARMv6 .deb package using config/pi-zero.toml"
	@echo "release-deb*-no-api  - the same .deb targets, dashboard only (e.g. release-deb-pi-zero-no-api)"
	@echo "release-deb*-api-only - the same .deb targets, JSON API only (e.g. release-deb-pi-zero-api-only)"

build:
	cargo build --workspace

build-release:
	cargo build --release --workspace

build-release-no-api:
	cargo build --release --no-default-features --features feat-web-ui

build-release-api-only:
	cargo build --release --no-default-features --features feat-json-api

build-pi-zero:
	cross build --release --target arm-unknown-linux-gnueabihf

build-pi-zero-no-api:
	cross build --release --target arm-unknown-linux-gnueabihf --no-default-features --features feat-web-ui

build-pi-zero-api-only:
	cross build --release --target arm-unknown-linux-gnueabihf --no-default-features --features feat-json-api

test:
	cargo test --workspace

test-variants:
	cargo test -p api --no-default-features --features feat-web-ui
	cargo test -p api --no-default-features --features feat-json-api

test-integration:
	cd tests/integration && GOTOOLCHAIN=go1.27.3 go test -count=1 -v -timeout 15m ./...

build-loadtest:
	mkdir -p target
	cd tests/dns-loadtest && GOTOOLCHAIN=go1.27.3 go build -trimpath -o ../../target/dns-loadtest .

test-loadtest:
	cd tests/dns-loadtest && GOTOOLCHAIN=go1.27.3 go test -race ./...
	cd tests/dns-loadtest && GOTOOLCHAIN=go1.27.3 go vet ./...

docker-up:
	docker compose -f deploy/docker-compose.yml up --build -d

docker-down:
	docker compose -f deploy/docker-compose.yml down

docker-rebuild:
	docker compose -f deploy/docker-compose.yml down -v
	docker compose -f deploy/docker-compose.yml build --no-cache
	docker compose -f deploy/docker-compose.yml up -d

release-deb:
	./deploy/build_deb.sh amd64

release-deb-arm64:
	./deploy/build_deb.sh arm64

release-deb-pi-zero:
	./deploy/build_pi_zero.sh

release-deb-no-api:
	VARIANT=no-api ./deploy/build_deb.sh amd64

release-deb-arm64-no-api:
	VARIANT=no-api ./deploy/build_deb.sh arm64

release-deb-pi-zero-no-api:
	VARIANT=no-api ./deploy/build_pi_zero.sh

release-deb-api-only:
	VARIANT=api-only ./deploy/build_deb.sh amd64

release-deb-arm64-api-only:
	VARIANT=api-only ./deploy/build_deb.sh arm64

release-deb-pi-zero-api-only:
	VARIANT=api-only ./deploy/build_pi_zero.sh
