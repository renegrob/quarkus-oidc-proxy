#!/bin/bash

helm template charts/oidc-proxy --values .values.yaml --namespace=oidc-proxy