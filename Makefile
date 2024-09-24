SHELL = /bin/sh
CURRENT_UID := $(shell id -u)

rebuild:
	DOCKER_BUILDKIT=1 docker compose up -d --build

shell:
	docker compose exec docidx bash

format:docs_processing
	black /
	ruff check --fix-only docs_processing/
	black tests/
	ruff check --fix-only tests/

fixperm:
	sudo chown -R $(CURRENT_UID) ./