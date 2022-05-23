#!/bin/bash

CONTAINER="oydid-cli"
REPOSITORY="oydeu"

# read commandline options
BUILD_CLEAN=false
DOCKER_UPDATE=false
BUILD_ARM=false
BUILD_X86=true

while [ $# -gt 0 ]; do
    case "$1" in
        --clean*)
            BUILD_CLEAN=true
            ;;
        --dockerhub*)
            DOCKER_UPDATE=true
            ;;
        --arm*)
            BUILD_X86=false
            BUILD_ARM=true
            ;;
        --x86*)
            BUILD_X86=true
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
    if $BUILD_X86; then
        docker build --platform linux/amd64 --no-cache -f ./docker/Dockerfile -t $REPOSITORY/$CONTAINER .
    fi
    if $BUILD_ARM; then
        docker build --platform linux/arm64 --no-cache -f ./docker/Dockerfile.arm64v8 -t $REPOSITORY/$CONTAINER:arm64v8 .
    fi    
else
    if $BUILD_X86; then
        docker build --platform linux/amd64 -f ./docker/Dockerfile -t $REPOSITORY/$CONTAINER .
    fi
    if $BUILD_ARM; then
        docker build --platform linux/arm64 -f ./docker/Dockerfile.arm64v8 -t $REPOSITORY/$CONTAINER:arm64v8 .
    fi
fi

if $DOCKER_UPDATE; then
    if $BUILD_X86; then
        docker push $REPOSITORY/$CONTAINER
    fi
    if $BUILD_ARM; then
        docker push $REPOSITORY/$CONTAINER:arm64v8
    fi
fi
