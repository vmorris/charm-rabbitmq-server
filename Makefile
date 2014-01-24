#!/usr/bin/make
PYTHON := /usr/bin/env python

lint:
	@flake8 --exclude lib/charmhelpers hooks
	@charm proof

sync:
	@charm-helper-sync -c charm-helpers.yaml

