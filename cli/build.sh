#!/bin/bash

CONTAINER="oydid-cli"
REPOSITORY="oydeu"

# read commandline options
BUILD_CLEAN=false
DOCKER_UPDATE=false
BUILD_LOCAL=false


while [ $# -gt 0 ]; do
    case "$1" in
        --clean*)
            BUILD_CLEAN=true
            ;;
        --dockerhub*)
            DOCKER_UPDATE=true
            ;;
        --local*)
            BUILD_LOCAL=true
            ;;
        *)
            printf "unknown option(s)\n"
            if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
                return 1
            else
                exit 1
            fi
    esac
    shift
done

if $BUILD_CLEAN; then
    if $BUILD_LOCAL; then
        docker build --platform linux/amd64 --no-cache -f ./docker/Dockerfile.local -t $REPOSITORY/$CONTAINER .
    else
        docker build --platform linux/amd64 --no-cache -f ./docker/Dockerfile -t $REPOSITORY/$CONTAINER .
    fi
else
    if $BUILD_LOCAL; then
        docker build --platform linux/amd64 -f ./docker/Dockerfile.local -t $REPOSITORY/$CONTAINER .
    else
        docker build --platform linux/amd64 -f ./docker/Dockerfile -t $REPOSITORY/$CONTAINER .
    fi
fi

if $DOCKER_UPDATE; then
    docker push $REPOSITORY/$CONTAINER
fi
