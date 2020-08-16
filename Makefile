.DEFAULT_GOAL := help

.PHONY: lint
lint: ## コードを検証します
	golangci-lint run

.PHONY: fmt
fmt: ## コードをフォーマットします
	@goimports -l -w .

.PHONY: benchmark
benchmark: ## ベンチマークを計測します
	@go test -bench . -benchmem

.PHONY: __
__:
	@echo "\033[33m"
	@echo "kzmake/benchmark-tokens"
	@echo "\tbenchmark jwt/paseto"
	@echo "\033[0m"

.PHONY: help
help: __ ## ヘルプを表示します
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@cat $(MAKEFILE_LIST) \
	| grep -e "^[a-zA-Z_/\-]*: *.*## *" \
	| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-24s\033[0m %s\n", $$1, $$2}'
