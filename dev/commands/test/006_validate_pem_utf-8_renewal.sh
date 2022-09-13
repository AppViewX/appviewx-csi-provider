echo ""
echo ""
echo "***** 006_validate_pem_utf-8_renewal *****" 
echo "-----------------------------------------------------------------------"
echo "Installing SecretProviderClass - pem - utf-8 - RENEWAL" 
echo "-----------------------------------------------------------------------"

kubectl delete secret cert-default-leaf-casetting-default-ca-casetting-default-selfsigned

cd /tmp
cat > appviewx-pki-secretproviderclass.yaml <<EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: appviewx-pki #name of the secretprovider
spec:
  provider: appviewx
  parameters:
    objectFormat: pem    # pem, pfx, p12, jks
    objectEncoding: utf-8     # utf-8, hex,  base64 
    objects: |
      - commonName: cert-default-leaf-casetting-default-ca-casetting-default-selfsigned.appviewx.com
        duration: 5m
        renewBefore: 4m
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
        privateKey:
          rotationPolicy: always          
EOF
kubectl apply -f ./appviewx-pki-secretproviderclass.yaml

echo "-----------------------------------------------------------------------"
echo "Installing Pod"
echo "-----------------------------------------------------------------------"

cd /tmp
cat > webapp-pod.yaml <<EOF
kind: Pod
apiVersion: v1
metadata:
  name: webapp
spec:
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
kubectl get pods -A | grep webapp | awk '{print $2}' | xargs kubectl delete pod --force
kubectl apply -f ./webapp-pod.yaml

echo "-----------------------------------------------------------------------"
echo "Validating"
echo "-----------------------------------------------------------------------"

cd /tmp
rm -rf ./appviewx-csi-provider-validation

mkdir appviewx-csi-provider-validation
cd ./appviewx-csi-provider-validation

mkdir certs
cd ./certs

for i in {20..1}; do printf "waiting for pod to ready: $i \r" && sleep 1; done

kubectl exec -it webapp -- cat /etc/ssl/tls.crt > ./tls1.crt
kubectl exec -it webapp -- cat /etc/ssl/tls.key > ./tls1.key
kubectl exec -it webapp -- cat /etc/ssl/ca.crt > ./ca1.crt

echo "---------------------------------------------------------------"                                              
echo "Getting md5sum and filesize"
echo "md5sum - ./ca1.crt  : $(md5sum ./ca1.crt) $(stat -c %s ./ca1.crt)"
echo "Getting SerialNumber"
echo "$(openssl x509 -in ./ca1.crt  -text -noout | grep -A1  "Serial Number:")"
echo "---------------------------------------------------------------"        
echo "Getting md5sum and filesize"
echo "md5sum - ./tls1.crt : $(md5sum ./tls1.crt) $(stat -c %s ./tls1.crt)"
echo "Getting SerialNumber"
echo "$(openssl x509 -in ./tls1.crt  -text -noout | grep -A1  "Serial Number:")"
echo "---------------------------------------------------------------"
echo "Getting md5sum and filesize"
echo "md5sum - ./tls1.key : $(md5sum ./tls1.key) $(stat -c %s ./tls1.key)"
echo "---------------------------------------------------------------" 

echo "Checking modulus of Certificate and Private Key"
echo "cert modulus - ./tls1.crt : $(openssl x509 -noout -modulus -in ./tls1.crt  | md5sum)"
echo "key modulus - ./tls1.key : $(openssl rsa -noout -modulus -in ./tls1.key  | md5sum)" 

echo "---------------------------------------------------------------" 
echo "Verifying Root to Leaf"                   
openssl verify -no_check_time -CAfile <(cat ./ca1.crt) ./tls1.crt
echo "---------------------------------------------------------------" 

for i in {120..1}; do printf "Waiting for Renewal to Finish: $i \r" && sleep 1; done

echo "---------------------------------------------------------------"                                              
echo "Renewal Finished"                                              
echo "---------------------------------------------------------------"                                              

kubectl exec -it webapp -- cat /etc/ssl/tls.crt > ./tls2.crt
kubectl exec -it webapp -- cat /etc/ssl/tls.key > ./tls2.key
kubectl exec -it webapp -- cat /etc/ssl/ca.crt > ./ca2.crt

echo "---------------------------------------------------------------"                                              
echo "Getting md5sum and filesize"
echo "md5sum - ./ca2.crt  : $(md5sum ./ca2.crt) $(stat -c %s ./ca2.crt)"
echo "Getting SerialNumber"
echo "$(openssl x509 -in ./ca2.crt  -text -noout | grep -A1  "Serial Number:")"
echo "---------------------------------------------------------------"        
echo "Getting md5sum and filesize"
echo "md5sum - ./tls2.crt : $(md5sum ./tls2.crt) $(stat -c %s ./tls2.crt)"
echo "Getting SerialNumber"
echo "$(openssl x509 -in ./tls2.crt  -text -noout | grep -A1  "Serial Number:")"
echo "---------------------------------------------------------------"
echo "Getting md5sum and filesize"
echo "md5sum - ./tls2.key : $(md5sum ./tls2.key) $(stat -c %s ./tls2.key)"
echo "---------------------------------------------------------------" 

echo "Checking modulus of Certificate and Private Key"
echo "cert modulus - ./tls2.crt : $(openssl x509 -noout -modulus -in ./tls2.crt  | md5sum)"
echo "key modulus - ./tls2.key : $(openssl rsa -noout -modulus -in ./tls2.key  | md5sum)" 

echo "---------------------------------------------------------------" 
echo "Verifying Root to Leaf"                   
openssl verify -no_check_time -CAfile <(cat ./ca2.crt) ./tls2.crt
echo "---------------------------------------------------------------" 
