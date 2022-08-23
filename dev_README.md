------------------------------------------------------------------------------------------------------------------------
Start cert-orchestrator

W1- cert-orchestrator-install
      R1-C1 - run
          cd /home/gopal.m/git/PRIVATE_REPOSITORIES/GROUPS/cnat/cert-orchestrator/dev/commands/run
          ./all.sh
          ./pod_all.sh
        
      R1-C2 - config
          cd /home/gopal.m/git/PRIVATE_REPOSITORIES/GROUPS/cnat/cert-orchestrator/config/samples

      R2 - logs
          cd /tmp
          kubectl logs   $(kubectl get pods -n cert-orchestrator-system |     awk '{ if(NR==2) print $1}' ) -n cert-orchestrator-system -c manager > /tmp/cert-orchestrator/log.txt && kubectl logs  -f $(kubectl get pods -n cert-orchestrator-system |     awk '{ if(NR==2) print $1}' ) -n cert-orchestrator-system -c manager >> /tmp/cert-orchestrator/log.txt;
      
      R3 - logs          
          cd /tmp/;tail -f ./cert-orchestrator/log.txt

W2 - cert-orchestrator-watch
      R1-C1 - pods
          watch kubectl get pods -A
      R1-C2 - certs
          watch kubectl get certs -A
      R2-C1 - secrets
          watch "kubetl get secrets -A | grep cert-"
      R3-c2 - certreq
          watch kubectl get certreq -A

------------------------------------------------------------------------------------------------------------------------
1. Install AppViewX Provider
------------------------------------------------------------------------------------------------------------------------
    
    cd /data/AppViewX/AI/TASKS/14.2022-2023/012_cert-orchestrator-JLR/vault-csi-provider-setup-certificates/appviewx-provider/helm_charts/appviewx-manifests/helm-manifests/appviewx
kubectl apply -f ./templates

------------------------------------------------------------------------------------------------------------------------
2. Install csi drive
----------------------------------------------------------------------------------------------------------------------------------------
	
    helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
	  helm install csi secrets-store-csi-driver/secrets-store-csi-driver --set syncSecret.enabled=true

----------------------------------------------------------------------------------------------------------------------------------------
3. Build Image
----------------------------------------------------------------------------------------------------------------------------------------

    make build
    make image

----------------------------------------------------------------------------------------------------------------------------------------
4. Restart the AppViewX-provider pod
----------------------------------------------------------------------------------------------------------------------------------------
    
    cd /home/gopal.m/git/PRIVATE_REPOSITORIES/GROUPS/cnat/appviewx-csi-provider;\
    make build;\
    make image;\
    kubectl get pods | grep provider | awk '{print $1}'  | xargs kubectl delete pod ;sleep 5;kubectl get pods | grep provider | awk '{print $1}'  | xargs kubectl logs -f 

----------------------------------------------------------------------------------------------------------------------------------------
5. Install all ( appviewx-provider-install )
----------------------------------------------------------------------------------------------------------------------------------------

cd /tmp
echo "Create Service Account"

cat > appviewx-auth-service-account.yaml <<EOF
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
   name: role-tokenreview-binding
   namespace: default
roleRef:
   apiGroup: rbac.authorization.k8s.io
   kind: ClusterRole
   name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: appviewx-auth    #Replace your custom service account name
  namespace: default  #Replace your custom namespace name here
EOF

kubectl create sa appviewx-auth
kubectl apply -f apviewx-auth-service-account.yaml

echo "Export Service account information for creating K8s auth"

export APPVIEWX_SA_NAME=$(kubectl get sa appviewx-auth --output jsonpath="{.secrets[*]['name']}")
export SA_JWT_TOKEN=$(kubectl get secret $APPVIEWX_SA_NAME --output 'go-template={{ .data.token }}' | base64 --decode)
export SA_CA_CRT=$(kubectl config view --raw --minify --flatten --output 'jsonpath={.clusters[].cluster.certificate-authority-data}' | base64 --decode)
export K8S_HOST=$(kubectl config view --raw --minify --flatten  --output 'jsonpath={.clusters[].cluster.server}')

echo $APPVIEWX_SA_NAME
echo $SA_JWT_TOKEN
echo $SA_CA_CRT
echo $K8S_HOST


echo "******* Setup kubernetes auth in vault 
( Manual 1. enable auth method -> kubernetes 2. echo $SA_CA_CRT format with certlogic.com 3. copy jwt token 4. disable jwt verifier  5. Access-> kubernetes create role   (pki_int_role - ISSUER ROLE ), 6. vault allowed domain demo.com"

read -p "Press any key to continue... " -n1 -s 

echo "******* Setup PKI engine in vault -> \
( *** DOCUMENT vault-setup )"

echo "Create secret provider class to talk to vault"

echo "( ************ create a role in pki_int )"

-------------------------------OLD-------------------------------------
cat > appviewx-pki-secretproviderclass.yaml <<EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: appviewx-pki #name of the secretprovider
spec:
  provider: appviewx
  parameters:
    roleName: "vault-csi"  #Role created for K8s auth in vault
    vaultAddress: http://192.168.236.56:5920  #Vault IP address and port
    #vaultCACertPath: /home/appviewx/vignesh/ca.crt
    # N.B. No secretKey means the whole JSON response will be written.
    objects: |
      - commonName: test.appviewx.com
        secretName: testsecret.com
        caSettingRef: 
          name: casetting-test-ca-casetting-test-selfsigned
          kind: CASetting
          group: cert-orchestrator.certplus.appviewx        
          
EOF
--------------------------------OLD------------------------------------

--------------------------------APPVIEWX------------------------------------
cat > appviewx-pki-secretproviderclass.yaml <<EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: appviewx-pki #name of the secretprovider
spec:
  provider: appviewx
  parameters:
    roleName: "vault-csi"  #Role created for K8s auth in vault
    vaultAddress: http://192.168.236.56:5920  #Vault IP address and port
    #vaultCACertPath: /home/appviewx/vignesh/ca.crt
    # N.B. No secretKey means the whole JSON response will be written.
    objects: |
      - commonName: cert-default-leaf-casetting-default-ca-casetting-default-selfsigned.appviewx.com
        duration: 12m
        subject:
          countries:
          - IN
          organizations:
          - AppViewX
          organizationalUnits:
          - Cert+
          localities:
          - CBE
          provinces:
          - TN
          streetAddresses:
          - Avinashi Road, Peelamedu
          postalCodes:
          - "641035"
        secretName: cert-default-leaf-casetting-default-ca-casetting-default-selfsigned
        caSettingRef: 
          name: casetting-default-ca-casetting-default-selfsigned
          kind: CASetting
          group: cert-orchestrator.certplus.appviewx
          
EOF
--------------------------------APPVIEWX------------------------------------

kubectl apply -f appviewx-pki-secretproviderclass.yaml

echo "Deploy sample app"

cat > webapp-pod.yaml <<EOF
kind: Pod
apiVersion: v1
metadata:
  name: webapp
spec:
  serviceAccountName: appviewx-auth # service account name created
  containers:
  - image: jweissig/app:0.0.1
    name: webapp
    volumeMounts:
    - name: secrets-store-inline
      #mountPath: "/mnt/secrets-store" #Path to mount the certificate data
      mountPath: "/etc/ssl/"           #Path to mount the certificate data
      readOnly: true
  volumes:
    - name: secrets-store-inline
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "appviewx-pki" #name of the secretprovider
EOF

kubectl apply -f webapp-pod.yaml

----------------------------------------------------------------------------------------------------------------------------------------
5. Restart web ( appviewx-provider-run )
----------------------------------------------------------------------------------------------------------------------------------------
    R1-C1 - pods
      kubectl get pods -A

    R1-C2 - restart web
      cd /tm
      kubectl delete pod webapp --force;kubectl apply -f ./webapp-pod.yaml

    R2 - logs
      cd /tmp
      kubectl get pods | grep provider | awk '{print $1}'  | xargs kubectl logs -f 

    
    kubectl delete pod webapp --force;kubectl apply -f webapp-pod.yaml

----------------------------------------------------------------------------------------------------------------------------------------


TODO:

    1. Cleanup cert-orchestrator dependencies, use clean module usage