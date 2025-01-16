GOFLAGS ?= $(GOFLAGS:)

VERSION=`git describe --abbrev=0 --tags`

ifdef BUILD_NUMBER
VERSION:=$(VERSION)+$(BUILD_NUMBER)
endif

define cucumber_image_build
    rm -rf ./aruba/bin/
	mkdir -p ./aruba/bin/ && cp ./bin/linux/vcert ./aruba/bin/vcert
	docker build --tag vcert.auto aruba/
endef

define cucumber_tests_run
    if [ -n "$(FEATURE)" ] && [ -n "$(PLATFORM)" ]; then \
		echo "running cucumber tests for both feature $(FEATURE) and platform $(PLATFORM)"; \
		cd aruba && ./cucumber.sh -a $(FEATURE) -b $(PLATFORM); \
	elif [ -n "$(FEATURE)" ]; then \
		echo "running cucumber tests for feature $(FEATURE)"; \
		cd aruba && ./cucumber.sh -a $(FEATURE); \
	elif [ -n "$(PLATFORM)" ]; then \
		echo "running cucumber tests for platform $(PLATFORM)"; \
		cd aruba && ./cucumber.sh -b $(PLATFORM); \
	else \
		echo "running all cucumber tests"; \
		cd aruba && ./cucumber.sh; \
    fi
endef

ifdef RELEASE_VERSION
ifneq ($(RELEASE_VERSION),none)
VERSION=$(RELEASE_VERSION)
endif
endif

GO_LDFLAGS=-ldflags "-X github.com/Venafi/vcert/v5.versionString=$(VERSION) -X github.com/Venafi/vcert/v5.versionBuildTimeStamp=`date -u +%Y%m%d.%H%M%S` -s -w"
version:
	echo "$(VERSION)"

get: gofmt
	go get $(GOFLAGS) ./...

build_quick: get
	env GOOS=linux   GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/linux/vcert         ./cmd/vcert

build: get
	env GOOS=linux   GOARCH=arm64 go build $(GO_LDFLAGS) -o bin/linux/vcert_arm       ./cmd/vcert
	env GOOS=linux   GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/linux/vcert           ./cmd/vcert
	env GOOS=linux   GOARCH=386   go build $(GO_LDFLAGS) -o bin/linux/vcert86         ./cmd/vcert
	env GOOS=darwin  GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/darwin/vcert          ./cmd/vcert
	env GOOS=darwin  GOARCH=arm64 go build $(GO_LDFLAGS) -o bin/darwin/vcert_arm      ./cmd/vcert
	env GOOS=windows GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/windows/vcert.exe     ./cmd/vcert
	env GOOS=windows GOARCH=386   go build $(GO_LDFLAGS) -o bin/windows/vcert86.exe   ./cmd/vcert
	env GOOS=windows GOARCH=arm64 go build $(GO_LDFLAGS) -o bin/windows/vcert_arm.exe ./cmd/vcert

cucumber_build:
	$(call cucumber_image_build)

cucumber_test:
	$(call cucumber_tests_run)

cucumber:
	$(call cucumber_image_build)
	$(call cucumber_tests_run)

gofmt:
	! gofmt -l . | grep -v ^vendor/ | grep .

test: get linter
	go test -v -coverprofile=cov1.out .
	go tool cover -func=cov1.out
	go test -v -coverprofile=cov2.out ./pkg/certificate
	go tool cover -func=cov2.out
	go test -v -coverprofile=cov3.out ./pkg/endpoint
	go tool cover -func=cov3.out
	go test -v -coverprofile=cov4.out ./pkg/venafi/fake
	go tool cover -func=cov4.out
	go test -v -coverprofile=cov5.out ./pkg/policy
	go tool cover -func=cov5.out
	go test -v -coverprofile=cov6.out ./pkg/util
	go tool cover -func=cov6.out
	go test -v -coverprofile=cov_cmd.out ./cmd/vcert
	go tool cover -func=cov_cmd.out

tpp_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_tpp.out ./pkg/venafi/tpp
	go tool cover -func=cov_tpp.out

cloud_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_vaas.out ./pkg/venafi/cloud
	go tool cover -func=cov_vaas.out

firefly_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_firefly.out ./pkg/venafi/firefly
	go tool cover -func=cov_firefly.out

cmd_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_cmd.out ./cmd/vcert
	go tool cover -func=cov_cmd.out

playbook_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_playbook.out ./pkg/playbook/...
	go tool cover -func=cov_playbook.out

collect_artifacts:
	rm -rf artifacts
	mkdir -p artifacts
	# we are assuming that signature are in the path were the make file was executed (not necessarily should be in the root of project)
	zip -j "artifacts/vcert_$(VERSION)_linux_arm.zip" "bin/linux/vcert_arm" "vcert_linux_arm.sig" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_linux.zip" "bin/linux/vcert" "vcert_linux.sig" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_linux86.zip" "bin/linux/vcert86" "vcert_linux86.sig" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_darwin.zip" "bin/darwin/vcert" "vcert_darwin.sig" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_darwin_arm.zip" "bin/darwin/vcert_arm" "vcert_darwin_arm.sig" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_windows.zip" "bin/windows/vcert.exe" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_windows86.zip" "bin/windows/vcert86.exe" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_windows_arm.zip" "bin/windows/vcert_arm.exe" || exit 1

release:
	echo '```' > release.txt
	cd artifacts; sha1sum * >> ../release.txt
	echo '```' >> release.txt
	go install github.com/tcnksm/ghr@v0.16.2
	export "PATH=$(PATH):$(shell go env GOPATH)/bin" && ghr -prerelease -n $$RELEASE_VERSION -body="$$(cat ./release.txt)" $$RELEASE_VERSION artifacts/

linter:
	@golangci-lint --version || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /go/bin
	golangci-lint run --timeout 5m
