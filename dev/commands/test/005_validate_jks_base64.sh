echo ""
echo ""
echo "***** 005_validate_jks_base64 *****" 
echo "-----------------------------------------------------------------------"
echo "Installing SecretProviderClass - jks - base64" 
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
    objectFormat: jks    # pem, pfx, p12, jks
    objectEncoding: base64     # utf-8, hex,  base64 
    objects: |
      - commonName: cert-default-leaf-casetting-default-ca-casetting-default-selfsigned.appviewx.com
        duration: 5m
        renewBefore: 3m
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

kubectl exec -it webapp -- cat /etc/ssl/tls.jks | base64 --decode > ./tls.jks
kubectl exec -it webapp -- cat /etc/ssl/aliasName > ./aliasName
kubectl exec -it webapp -- cat /etc/ssl/aliasPassword > ./aliasPassword
kubectl exec -it webapp -- cat /etc/ssl/jksPassword > ./jksPassword

echo "Generating .p12 file"
keytool -importkeystore -srckeystore ./tls.jks \
                        -destkeystore ./tls.p12 \
                        -srcstoretype JKS \
                        -deststoretype PKCS12 \
                        -deststorepass testtest \
                        -srcstorepass $(cat ./jksPassword) \
                        -srckeypass $(cat ./aliasPassword) \
                        -srcalias $(cat ./aliasName) \
                        -destkeypass testtest


openssl pkcs12 -in ./tls.p12   -passin pass:testtest --passout pass:testtest -nocerts -nodes | sed -ne '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' > ./tls.key
openssl pkcs12 -in ./tls.p12   -passin pass:testtest --passout pass:testtest -clcerts -nokeys | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ./tls.crt
openssl pkcs12 -in ./tls.p12   -passin pass:testtest --passout pass:testtest -cacerts -nokeys  -chain | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ./ca.crt

echo "---------------------------------------------------------------"                                              
echo "Getting md5sum and filesize"
echo "md5sum - ./ca.crt  : $(md5sum ./ca.crt) $(stat -c %s ./ca.crt)"
echo "Getting SerialNumber"
echo "$(openssl x509 -in ./ca.crt  -text -noout | grep -A1  "Serial Number:")"
echo "---------------------------------------------------------------"        
echo "Getting md5sum and filesize"
echo "md5sum - ./tls.crt : $(md5sum ./tls.crt) $(stat -c %s ./tls.crt)"
echo "Getting SerialNumber"
echo "$(openssl x509 -in ./tls.crt  -text -noout | grep -A1  "Serial Number:")"
echo "---------------------------------------------------------------"
echo "Getting md5sum and filesize"
echo "md5sum - ./tls.key : $(md5sum ./tls.key) $(stat -c %s ./tls.key)"
echo "---------------------------------------------------------------" 

echo "Checking modulus of Certificate and Private Key"
echo "cert modulus - ./tls.crt : $(openssl x509 -noout -modulus -in ./tls.crt  | md5sum)"
echo "key modulus - ./tls.key : $(openssl rsa -noout -modulus -in ./tls.key  | md5sum)" 

echo "---------------------------------------------------------------" 
echo "Verifying Root to Leaf"                   
openssl verify -no_check_time -CAfile <(cat ./ca.crt) ./tls.crt
echo "---------------------------------------------------------------" 