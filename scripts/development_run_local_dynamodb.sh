#!/usr/bin/env nix-shell
#! nix-shell -i bash
#! nix-shell -p bash docker awscli

export AWS_ACCESS_KEY_ID=DEVKEYID
export AWS_SECRET_ACCESS_KEY=DEVSECRETKEY aws
TABLE_NAME="local-development"

trap ctrl_c INT
function ctrl_c() {
    echo "Aborting"
    docker rm -f dynamodb-development >/dev/null 2>&1
}

docker rm -f dynamodb-development >/dev/null 2>&1

echo "starting dynamodb local instance" 2>&1
docker run -p 8000:8000 --name dynamodb-development -d amazon/dynamodb-local >/dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "could not start dynamodb local instance" >&2
    exit 1
fi

echo "creating dynamodb table" 2>&1
aws \
    --region us-east-1 dynamodb \
    --endpoint-url http://localhost:8000 create-table \
    --table-name "$TABLE_NAME" \
    --key-schema AttributeName=pk,KeyType=HASH \
    --attribute-definition \
        AttributeName=pk,AttributeType=S \
    --provisioned-throughput ReadCapacityUnits=500,WriteCapacityUnits=500 >/dev/null

if [ $? -ne 0 ]
then
    echo "could not create dynamodb table" >&2
    exit 1
fi

echo "running app" 2>&1
go run ./cmd/seshador vault --insecure-no-tls --storage "dynamodb://us-east-1/${TABLE_NAME}"
