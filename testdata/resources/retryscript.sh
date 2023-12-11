#!/bin/bash

retries=3
until [ $retries -le 0 ]; do
  response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:7990/status)
  if [ "$response" = "200" ]; then
    echo "Success! Status code 200 received."
    break
  else
    echo "Status code $response received. Retrying in 5 seconds..."
    sleep 5
    retries=$((retries - 1))
  fi
done