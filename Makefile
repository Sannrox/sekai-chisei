SHELL := /bin/sh

CARGO ?= cargo
PROTO_CONTRACTS := sekai.proto chisei.proto
# Cargo's --tests also runs unit-test targets; select integration targets explicitly.
INTEGRATION_TESTS := $(sort $(patsubst tests/%.rs,%,$(wildcard tests/*.rs)))

.PHONY: test validate test-integration update

test:
	$(CARGO) test --workspace --lib --bins --locked

validate:
	$(CARGO) fmt --all -- --check
	$(CARGO) check --workspace --all-targets --locked
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

test-integration:
	@if [ -z "$(INTEGRATION_TESTS)" ]; then \
		echo "No integration test targets found under tests/" >&2; \
		exit 1; \
	fi
	$(CARGO) test --workspace $(foreach test,$(INTEGRATION_TESTS),--test $(test)) --locked

update:
	@for name in $(PROTO_CONTRACTS); do \
		if ! cmp -s "proto/$$name" "crates/sekai-proto/proto/$$name"; then \
			cp "proto/$$name" "crates/sekai-proto/proto/$$name"; \
			echo "Updated crates/sekai-proto/proto/$$name"; \
		fi; \
	done
