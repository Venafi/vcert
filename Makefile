GOFLAGS ?= $(GOFLAGS:)

VERSION=`git describe --abbrev=0 --tags`

ifdef BUILD_NUMBER
VERSION:=$(VERSION)+$(BUILD_NUMBER)
endif

ifdef RELEASE_VERSION
ifneq ($(RELEASE_VERSION),none)
VERSION=$(RELEASE_VERSION)
endif
endif

GO_LDFLAGS=-ldflags "-X github.com/Venafi/vcert/v4.versionString=$(VERSION) -X github.com/Venafi/vcert/v4.versionBuildTimeStamp=`date -u +%Y%m%d.%H%M%S` -s -w"
version:
	echo "$(VERSION)"

get: gofmt
	go get $(GOFLAGS) ./...

build_quick: get
	env GOOS=linux   GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/linux/vcert         ./cmd/vcert

build: get
	env GOOS=linux   GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/linux/vcert         ./cmd/vcert
	env GOOS=linux   GOARCH=386   go build $(GO_LDFLAGS) -o bin/linux/vcert86       ./cmd/vcert
	env GOOS=darwin  GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/darwin/vcert        ./cmd/vcert
	env GOOS=windows GOARCH=amd64 go build $(GO_LDFLAGS) -o bin/windows/vcert.exe   ./cmd/vcert
	env GOOS=windows GOARCH=386   go build $(GO_LDFLAGS) -o bin/windows/vcert86.exe ./cmd/vcert

cucumber:
	rm -rf ./aruba/bin/
	mkdir -p ./aruba/bin/ && cp ./bin/linux/vcert ./aruba/bin/vcert
	docker build --tag vcert.auto aruba/
	if [ -z "$(FEATURE)" ]; then \
		cd aruba && ./cucumber.sh; \
	else \
		cd aruba && ./cucumber.sh $(FEATURE); \
	fi

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
	go test -v -coverprofile=cov_cmd.out ./cmd/vcert
	go tool cover -func=cov_cmd.out

tpp_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_tpp.out ./pkg/venafi/tpp
	go tool cover -func=cov_tpp.out

cloud_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_vaas.out ./pkg/venafi/cloud
	go tool cover -func=cov_vaas.out

cmd_test: get
	go test -v $(GOFLAGS) -coverprofile=cov_cmd.out ./cmd/vcert
	go tool cover -func=cov_cmd.out

collect_artifacts:
	rm -rf artifacts
	mkdir -p artifacts
	zip -j "artifacts/vcert_$(VERSION)_linux.zip" "bin/linux/vcert" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_linux86.zip" "bin/linux/vcert86" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_darwin.zip" "bin/darwin/vcert" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_windows.zip" "bin/windows/vcert.exe" || exit 1
	zip -j "artifacts/vcert_$(VERSION)_windows86.zip" "bin/windows/vcert86.exe" || exit 1

release:
	echo '```' > release.txt
	cd artifacts; sha1sum * >> ../release.txt
	echo '```' >> release.txt
	go get -u github.com/tcnksm/ghr
	ghr -prerelease -n $$RELEASE_VERSION -body="$$(cat ./release.txt)" $$RELEASE_VERSION artifacts/

linter:
	@golangci-lint --version || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /go/bin
	golangci-lint run
