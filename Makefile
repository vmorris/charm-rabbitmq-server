#!/usr/bin/make

lint:
	@echo -n "Running flake8 tests: "
	@flake8 --exclude hooks/charmhelpers hooks
	@flake8 unit_tests
	@echo "OK"
	@echo -n "Running charm proof: "
	@charm proof
	@echo "OK"

sync:
	@charm-helper-sync -c charm-helpers.yaml

all: test lint
