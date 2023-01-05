#!/usr/bin/env bash

OYDIDCMD='../oydid.rb'
# export OYDIDCMD='oydid'

# CONTAINER_NAME=test_sc_1
export CONTAINER_NAME=oydid

# start local Semantic Container and get access token
export SEMCON_URL='http://localhost:4000'
# SEMCON_URL='https://demo.data-container.net'
docker rm -f oydid
IMAGE=semcon/sc-base:latest; docker run -d --name $CONTAINER_NAME -p 4000:3000 -e AUTH=true \
    -e IMAGE_SHA256="$(docker image ls --no-trunc -q $IMAGE | tail -1)" \
    -e IMAGE_NAME=$IMAGE \
    -e SERVICE_ENDPOINT="http://192.168.178.21:4000" $IMAGE
#    -e SERVICE_ENDPOINT="http://10.0.0.16:4000" $IMAGE
# wait until container started
bash -c 'while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' $SEMCON_URL/api/active)" != "200" ]]; do sleep 3; done'
sleep 10
APP_KEY=`docker logs $CONTAINER_NAME | grep APP_KEY | awk -F " " '{print $NF}'`; \
APP_SECRET=`docker logs $CONTAINER_NAME | grep APP_SECRET | awk -F " " '{print $NF}'`; \
export ADMIN_TOKEN=`curl -s -d grant_type=client_credentials -d client_id=$APP_KEY \
    -d client_secret=$APP_SECRET -d scope=admin \
    -X POST $SEMCON_URL/oauth/token | jq -r '.access_token'`
# export TOKEN=`curl -X POST -s -d grant_type=client_credentials -d scope=admin \
#     -d client_id=c196066b21eeb9df20056447467d7132696d7558a3208610e0dab6941a9434b8 \
#     -d client_secret=fb6f99f75e2d37943c4a8f9196dd07ed96daeef525a88d03c2246093074973c6 \
#     $SEMCON_URL/oauth/token | \
#     jq -r '.access_token'`
# echo "Admin Token: $ADMIN_TOKEN"
# echo "SC_URL: $SEMCON_URL"
# $OYDIDCMD sc_init -l $SEMCON_URL --token $ADMIN_TOKEN --doc-key c2/private_key.enc --rev-key c2/revocation_key.enc

# # create DID for Semantic Container
SC_DID=`$OYDIDCMD sc_init -l $SEMCON_URL --token $ADMIN_TOKEN --doc-key c2/private_key.enc --rev-key c2/revocation_key.enc |
    jq -r '.did'`
echo "DID: $SC_DID"

# writing to Semantic Container
TOKEN=`$OYDIDCMD sc_token $SC_DID --doc-key c2/private_key.enc | \
    jq -r '.access_token'`
echo '{"hello": "world"}' | \
    curl -s -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
    -d @- -X POST $SEMCON_URL/api/data

# reading from SEMANTIC CONTAINER
curl -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -X GET $SEMCON_URL/api/data

# create DID for record
cat c2/data.json | $OYDIDCMD sc_create $SC_DID --doc-pwd=pwd3 --rev-pwd=pwd4 --token $ADMIN_TOKEN

# # output DID
# $OYDIDCMD read --w3c-did "$DID_REC;$SEMCON_URL"