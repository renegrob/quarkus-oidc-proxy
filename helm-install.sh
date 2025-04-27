#!/bin/bash

./gradlew imageBuild

docker save renegrob/oidc-proxy-cb:latest -o oidc-proxy-cb.tar
microk8s ctr image import oidc-proxy-cb.tar
microk8s ctr images tag docker.io/renegrob/oidc-proxy-cb:latest renegrob/oidc-proxy-cb:latest

helm upgrade --install --atomic oidc-proxy charts/oidc-proxy-cb --values .values.yaml --namespace=oidc-proxy --create-namespace --timeout=600s --wait
