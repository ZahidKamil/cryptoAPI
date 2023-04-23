#! usr/bin/bash
kubectl delete deployment server
kubectl delete deployment client
kubectl delete service server-service
kubectl delete configmap server-service-config


