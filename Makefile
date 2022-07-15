.PHONY: tests
tests: vendor ## Run all tests
	vendor/bin/phpunit  --color
	yarn test

.PHONY: cc
cc: vendor ## Show test coverage rates (HTML)
	vendor/bin/phpunit --coverage-html ./build

.PHONY: cs
cs: vendor ## Fix all files using defined ECS rules
	vendor/bin/ecs check --fix

.PHONY: st
st: vendor ## Run static analyse
	vendor/bin/phpstan analyse

################################################

.PHONY: ci-cc
ci-cc: vendor ## Show test coverage rates (for CI/CD only)
	vendor/bin/phpunit --coverage-text

.PHONY: ci-cs
ci-cs: vendor ## Check all files using defined ECS rules (for CI/CD only)
	vendor/bin/ecs check

################################################

.PHONY: rector
rector: vendor ## Check all files using Rector
	vendor/bin/rector process --ansi --dry-run --xdebug

vendor: composer.json
	composer validate
	composer install

.DEFAULT_GOAL := help
help:
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'
.PHONY: help
