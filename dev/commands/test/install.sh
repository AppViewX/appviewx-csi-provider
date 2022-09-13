echo "-----------------------------------------------------------------------"
echo "configuring cert-orchestrator"
echo "-----------------------------------------------------------------------"

cd /home/gopal.m/git/PRIVATE_REPOSITORIES/GROUPS/cnat/cert-orchestrator/config/samples
kubectl apply -f ./001_self_signed/casetting/;
kubectl apply -f ./001_self_signed/cert;
kubectl apply -f ./002_secret_as_ca-leaf/casetting/;
kubectl apply -f ./012_renewal_appviewx/renewaljob/cert-orchestrator_v1_renewaljob.yaml 

echo "-----------------------------------------------------------------------"
echo "Installing appviewx-csi-provider"
echo "-----------------------------------------------------------------------"

kubectl create namespace appviewx-csi-provider

cd /data/AppViewX/AI/TASKS/14.2022-2023/012_cert-orchestrator-JLR/vault-csi-provider-setup-certificates/appviewx-provider/op/otherNamespace/helm_charts/appviewx-manifests/helm-manifests/appviewx
kubectl apply -f ./templates

echo "-----------------------------------------------------------------------"
echo "Installing kubernetes-csi-driver"
echo "-----------------------------------------------------------------------"

helm install csi secrets-store-csi-driver/secrets-store-csi-driver --namespace appviewx-csi-provider --set syncSecret.enabled=true --set enableSecretRotation=true  --set rotationPollInterval=1m  

