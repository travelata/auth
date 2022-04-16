# Auth service

## Description
**auth** service is responsible for ...

## Installation

* make sure you have `make` installed
* make sure you have `golangci-lint`, `goose` installed
* copy `.env-default` to `.env`
* populate env variables according to your environment

###### Local Build
````
# build a service
make build

# check and load dependencies
make dep

# apply lint
make lint
````

###### Docker Build & Push
````
# build an image with a tag specified by $(DOCKER_TAG)
make docker-build

# pash image with a tag specified by $(DOCKER_TAG)
make docker-push
````

###### Database migrations
````
# run an initialization script (create and configure your secrice's schema)
make db-init-schem

# current version
make db-status

# apply migratiosn up to the last version
make db-up

# unapply migrations
make db-down
````

## Environment variables

| name          | description                                                          |default value|
|---------------|----------------------------------------------------------------------|-------------|
| TRAVELATAROOT | Folder where all your services are cloned                            ||
| GITHUB_USER   | Github account. Used for loading go modules from private github repo ||
| GITHUB_TOKEN  | Github token. Used for loading go modules from private github repo   ||

## Owner

**Name:** Nikita Zaitsev

**Email:** exluap@icloud.com




