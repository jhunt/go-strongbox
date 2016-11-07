ARTIFACTS := artifacts/strongbox-{{.OS}}-{{.Arch}}
LDFLAGS := -X main.Version=$(VERSION)
release:
	@echo "Checking that VERSION was defined in the calling environment"
	@test -n "$(VERSION)"
	@echo "OK.  VERSION=$(VERSION)"

	gox -osarch="linux/amd64" -ldflags="$(LDFLAGS)" --output="$(ARTIFACTS)"
