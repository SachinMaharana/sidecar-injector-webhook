cluster_name := "noms"
docker_user := "sachinnicky"
binary := "sidecar-injector-webhook"
default_namespace := "default"

cluster-up:
    kind create cluster --name {{cluster_name}} --image kindest/node:v1.19.1  --config ./kind-config.yaml
    sleep "10"
    kubectl wait --namespace kube-system --for=condition=ready pod --selector="tier=control-plane" --timeout=180s

certs:
    ./gencert.sh --service {{binary}} --secret webhook-tls-certs --namespace {{default_namespace}}

ca default=default_namespace:
    #!/bin/bash
    CA_BUNDLE=$(kubectl get secrets -n {{default}} webhook-tls-certs -ojson | jq '.data."caCert.pem"')
    export CA_BUNDLE=${CA_BUNDLE}
    cat deploy/webhook.yaml | envsubst > deploy/webhook-ca.yaml
    kubectl apply -f deploy/webhook-ca.yaml

build:
    cargo build --release && cp target/release/{{binary}} . && docker build -t {{docker_user}}/{{binary}} -f Dockerfile . 
    
build-ci:
    docker build -t {{docker_user}}/{{binary}} .

load:
    kind --name {{cluster_name}} load docker-image {{docker_user}}/{{binary}}:latest

deploy:
    kubectl apply -f deploy/deployment.yaml
    kubectl rollout status deployment/{{binary}}

debug:
    kubectl apply -f deploy/debug.yaml

cluster-down:
    kind delete cluster --name {{cluster_name}}

all: cluster-up certs ca build load deploy

dl:
    kubectl delete -f deploy/deployment.yaml -f deploy/debug.yaml