#!/bin/bash

helm template charts/oidc-proxy-cb --values .values.yaml --namespace=oidc-proxy-cb