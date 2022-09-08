kubectl delete namespace appviewx-csi-provider
kubectl delete pods -A | grep webapp | awk '{print $2}' | xargs kubectl delete pod --force
