# -*- makefile -*-
.PHONY: deb deb-build-env deb-enter-docker

deb-build-env:
	docker build \
		-f ./debian/Dockerfile \
		-t python-deb-pkg \
		./

deb: deb-build-env
	docker run --rm \
		--volume="$(CURDIR)/debian/dist:/dist" \
		python-deb-pkg

deb-enter-docker:
	docker run --rm -ti \
		-v $$(pwd):/tmp/python-deb-pkg \
		python-deb-pkg /bin/bash
