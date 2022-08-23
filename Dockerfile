# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.

# devbuild compiles the binary
# -----------------------------------
FROM docker.mirror.hashicorp.services/golang:1.17.6 AS devbuild
ENV CGO_ENABLED=0
# Leave the GOPATH
WORKDIR /build
COPY . ./
RUN go build -trimpath -v -ldflags "-X 'main.gitCommit=8e4789c238e7bc97350d69df8a79f002643939e6' -X 'main.version=1.0_alpha.0' -X 'main.buildTime=$(date)'" -a -o appviewx-csi-provider

# dev runs the binary from devbuild
# -----------------------------------
FROM docker.mirror.hashicorp.services/alpine:3.15.0 AS dev
COPY --from=devbuild /build/appviewx-csi-provider /bin/
ENTRYPOINT [ "/bin/appviewx-csi-provider" ]

# Default release image.
# -----------------------------------
FROM docker.mirror.hashicorp.services/alpine:3.15.0 AS default

ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=appviewx-csi-provider
ARG TARGETOS TARGETARCH

LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION

COPY dist/$TARGETOS/$TARGETARCH/appviewx-csi-provider /bin/
ENTRYPOINT [ "/bin/appviewx-csi-provider" ]

# ===================================
# 
#   Set default target to 'dev'.
#
# ===================================
FROM dev
