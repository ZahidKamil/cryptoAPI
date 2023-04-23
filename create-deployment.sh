#! usr/bin/bash
kubectl apply -f server-deployment.yaml
kubectl apply -f server-service.yaml
kubectl apply -f server-service-config.yaml
kubectl apply -f client-deployment.yaml
kubectl get pods
