SHELL := /bin/sh
.EXPORT_ALL_VARIABLES:

WHAT ?=

.PHONY: all check docker gateway-smoke release-images test test-integration update validate

# Build release binaries.
# Example: make all
#          make all WHAT=sekaictl
all:
	bash ./scripts/make-targets/build.sh $(WHAT)

# Run every scripts/validate-*.sh script.
# Example: make validate
validate:
	bash ./scripts/make-targets/validate.sh

# Run every scripts/update-*.sh script.
# Example: make update
update:
	bash ./scripts/make-targets/update.sh

# Example: make test
#          make test WHAT=--lib
#          make test WHAT='--test compatibility_matrix'
test:
	bash ./scripts/make-targets/test.sh $(WHAT)

test-integration:
	bash ./scripts/make-targets/test.sh --tests

# The local and CI gate.
check: all test validate

docker:
	bash ./scripts/make-targets/docker.sh

gateway-smoke:
	bash ./scripts/make-targets/gateway-smoke.sh

release-images:
	bash ./build/release-images.sh
