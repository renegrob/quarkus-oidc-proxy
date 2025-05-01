#!/bin/bash

./gradlew imageBuild

docker save renegrob/oidc-proxy:latest -o oidc-proxy.tar
microk8s ctr image import oidc-proxy.tar
microk8s ctr images tag docker.io/renegrob/oidc-proxy:latest renegrob/oidc-proxy:latest

helm upgrade --install --atomic oidc-proxy charts/oidc-proxy --values .values.yaml --namespace=oidc-proxy --create-namespace --timeout=600s --wait
