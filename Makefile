# load env variables from .env
ENV_PATH ?= ./.env
ifneq ($(wildcard $(ENV_PATH)),)
    include .env
    export
endif

# service code
SERVICE = auth

# current version
DOCKER_TAG ?= latest
# docker registry url
DOCKER_URL = ghcr.io/travelata

# database migrations
DB_ADMIN_USER ?= admin
DB_ADMIN_PASSWORD ?= admin
DB_HOST ?= localhost
DB_NAME ?= travelata
DB_AUTH_USER ?= auth
DB_AUTH_PASSWORD ?= auth

DB_DRIVER = postgres
DB_STRING = "user=$(DB_AUTH_USER) password=$(DB_AUTH_PASSWORD) dbname=$(DB_NAME) host=$(DB_HOST) sslmode=disable"
DB_ADMIN_STRING = "user=$(DB_ADMIN_USER) password=$(DB_ADMIN_PASSWORD) dbname=$(DB_NAME) host=$(DB_HOST) sslmode=disable"
DB_INIT_FOLDER = "./db/init"
DB_MIG_FOLDER = "./db/migrations"


# Build commands =======================================================================================================

dep:
	go env -w GO111MODULE=on
	go env -w GOPRIVATE=github.com/travelata/*
	go mod tidy

check-lint-installed:
	@if ! [ -x "$$(command -v golangci-lint)" ]; then \
		echo "golangci-lint is not installed"; \
		exit 1; \
	fi; \

lint: check-lint-installed
	@echo Running golangci-lint
	golangci-lint run ./...
	go fmt

mock: # generate mocks
	@rm -R ./mocks 2> /dev/null; \
	mockery --all

build: lint dep ## builds the main
	mkdir -p bin
	go build -o bin/ cmd/main.go

artifacts: mock build ## builds and generates all artifacts

run: ## run the service
	./bin/main

# setup kit version
# "version" - obligatory param
#  if version=local setup replace to local path
#
# examples:
# set version: make kit-version version=v0.1.1
# set local dev: make kit-version version=local
kit-version:
	@if [ -z $(version) ]; then \
  		echo "no version specified"; \
  	else \
		go mod edit -droprequire github.com/travelata/kit; \
		if [ $(version) = "local" ]; then \
			go mod edit -require=github.com/travelata/kit@v0.0.0-local; \
			go mod edit -replace=github.com/travelata/kit=./kit; \
			echo "changing kit version = "$(version); \
			go mod edit -droprequire github.com/travelata/kit; \
			go mod edit -require=github.com/travelata/kit@v0.0.0-local; \
			go mod edit -replace=github.com/travelata/kit=../kit; \
			if [ $(version) = "local" ]; then \
				go mod edit -require=github.com/travelata/kit@v0.0.0-local; \
				go mod edit -replace=github.com/travelata/kit=../kit; \
			else \
				go mod edit -require=github.com/travelata/kit@$(version); \
				go mod edit -replace=github.com/travelata/kit=github.com/travelata/kit.git@$(version); \
			fi ;\
		else \
			go mod edit -require=github.com/travelata/kit@$(version); \
			go mod edit -replace=github.com/travelata/kit=github.com/travelata/kit.git@$(version); \
			echo "changing kit version = "$(version); \
			go mod edit -droprequire github.com/travelata/kit; \
			go mod edit -require=github.com/travelata/kit@$(version); \
			go mod edit -replace=github.com/travelata/kit=github.com/travelata/kit.git@$(version); \
		fi ;\
  	fi

# setup proto version
# "version" - obligatory param
#  if version=local setup replace to local path
#
# examples:
# set version: make proto-version version=v0.1.1
# set local dev: make proto-version version=local
proto-version:
	@if [ -z $(version) ]; then \
  		echo "no version specified"; \
  	else \
		go mod edit -droprequire github.com/travelata/proto; \
		if [ $(version) = "local" ]; then \
			go mod edit -require=github.com/travelata/proto@v0.0.0-local; \
			go mod edit -replace=github.com/travelata/proto=./proto; \
			echo "changing proto version = "$(version); \
			go mod edit -droprequire github.com/travelata/proto; \
			go mod edit -require=github.com/travelata/proto@v0.0.0-local; \
			go mod edit -replace=github.com/travelata/proto=../proto; \
			if [ $(version) = "local" ]; then \
				go mod edit -require=github.com/travelata/proto@v0.0.0-local; \
				go mod edit -replace=github.com/travelata/proto=../proto; \
			else \
				go mod edit -require=github.com/travelata/proto@$(version); \
				go mod edit -replace=github.com/travelata/proto=github.com/travelata/proto.git@$(version); \
			fi ;\
		else \
			go mod edit -require=github.com/travelata/proto@$(version); \
			go mod edit -replace=github.com/travelata/proto=github.com/travelata/proto.git@$(version); \
			echo "changing proto version  = "$(version); \
			go mod edit -droprequire github.com/travelata/proto; \
			go mod edit -require=github.com/travelata/proto@$(version); \
			go mod edit -replace=github.com/travelata/proto=github.com/travelata/proto.git@$(version); \
		fi ;\
  	fi



# Database commands ====================================================================================================

check-goose-installed:
	@if ! [ -x "$$(command -v goose)" ]; then \
		echo "goose is not installed"; \
		exit 1; \
	fi; \

db-init-schema:
	GOOSE_DRIVER=$(DB_DRIVER) GOOSE_DBSTRING=$(DB_ADMIN_STRING) goose -dir $(DB_INIT_FOLDER) up

db-status: check-goose-installed
	GOOSE_DRIVER=$(DB_DRIVER) GOOSE_DBSTRING=$(DB_STRING) goose -dir $(DB_MIG_FOLDER) status

db-up: check-goose-installed
	GOOSE_DRIVER=$(DB_DRIVER) GOOSE_DBSTRING=$(DB_STRING) goose -dir $(DB_MIG_FOLDER) up

db-down: check-goose-installed
	GOOSE_DRIVER=$(DB_DRIVER) GOOSE_DBSTRING=$(DB_STRING) goose -dir $(DB_MIG_FOLDER) down

db-create: check-goose-installed
	@if [ -z $(name) ]; then \
      	echo "usage: make db-create name=<you-migration-name>"; \
    else \
		GOOSE_DRIVER=$(DB_DRIVER) GOOSE_DBSTRING=$(DB_STRING) goose -dir $(DB_MIG_FOLDER) create $(name) sql; \
	fi

# Tests commands =======================================================================================================

test: ## run the tests
	@echo "running tests (skipping stateful)"
	go test ./...

test-with-coverage: ## run the tests with coverage
	@echo "running tests with coverage file creation (skipping integration)"
	go test -coverprofile .testCoverage.txt -v ./...

test-integration: ## run the integration tests
	@echo "running integration tests"
	go test -tags integration ./...

# Docker commands =======================================================================================================

docker-build: ## Build the docker images for all services (build inside)
	@echo Building images
	docker build . -f ./Dockerfile -t $(DOCKER_URL)/$(SERVICE):$(DOCKER_TAG) --no-cache --build-arg GITHUB_USER --build-arg GITHUB_TOKEN

docker-push: docker-build ## Build and push docker images to the repository
	@echo Pushing images
	docker push $(DOCKER_URL)/$(SERVICE):$(DOCKER_TAG)

docker-run:
	@echo Running container
	docker run $(DOCKER_URL)/$(SERVICE):$(DOCKER_TAG)

# CI/CD github commands =================================================================================================

ci-check-mocks:
	@mv ./mocks ./mocks-init
	mockery --all
	mockshash=$$(find ./mocks -type f -print0 | sort -z | xargs -r0 md5sum | awk '{print $$1}' | md5sum | awk '{print $$1}'); \
	mocksinithash=$$(find ./mocks-init -type f -print0 | sort -z | xargs -r0 md5sum | awk '{print $$1}' | md5sum | awk '{print $$1}'); \
	echo $$mockshash $$mocksinithash; \
	if ! [ "$$mockshash" = "$$mocksinithash" ] ; then \
	  echo "Mocks should be updated!" ; \
	  exit 1 ; \
	fi

ci-check: ci-check-mocks

ci-build: test-with-coverage docker-build docker-push

ci-build-mr: test-with-coverage docker-build