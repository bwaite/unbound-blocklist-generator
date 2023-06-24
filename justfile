
build-release:
    go build -buildmode=pie -trimpath -ldflags="-s -w" -mod=readonly -modcacherw
    # this fails to build since extldflags isn't defined. Not sure if it's only available in some compilers
    # see https://dubo-dubon-duponey.medium.com/a-beginners-guide-to-cross-compiling-static-cgo-pie-binaries-golang-1-16-792eea92d5aa
    # go build -buildmode=pie -ldflags="-s -w" -extldflags=-Wl,-z,now,-z,relro ./main.go

gcc-build-release:
    go build -buildmode=pie -compiler gccgo -gccgoflags "-s -w"


update-modules:
    go get -u
    go mod tidy

test:
    go test -v

coverage:
    go test -cover

gosec:
    gosec *.go

install:
    sudo cp main /usr/local/bin/blocklist-generator
