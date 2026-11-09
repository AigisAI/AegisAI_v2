FROM alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034
RUN apk add --no-cache ca-certificates
RUN wget -qO /tmp/opengrep.tar.gz https://github.com/opengrep/opengrep/releases/download/v1.33.1/opengrep-core_linux_x86.tar.gz \
 && echo '1a78593c369cd58a8545a1dfb2ce548139f028a1af4ea7d08bc5ce8385cde243  /tmp/opengrep.tar.gz' | sha256sum -c - \
 && tar -xzOf /tmp/opengrep.tar.gz opengrep-core > /usr/local/bin/opengrep-core \
 && chmod 0755 /usr/local/bin/opengrep-core
RUN wget -qO /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz \
 && echo 'bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf  /tmp/trivy.tar.gz' | sha256sum -c - \
 && tar -xzOf /tmp/trivy.tar.gz trivy > /usr/local/bin/trivy \
 && chmod 0755 /usr/local/bin/trivy
RUN wget -qO /tmp/syft.tar.gz https://github.com/anchore/syft/releases/download/v1.57.0/syft_1.57.0_linux_amd64.tar.gz \
 && echo '9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704  /tmp/syft.tar.gz' | sha256sum -c - \
 && tar -xzOf /tmp/syft.tar.gz syft > /usr/local/bin/syft \
 && chmod 0755 /usr/local/bin/syft
RUN rm -f /tmp/opengrep.tar.gz /tmp/trivy.tar.gz /tmp/syft.tar.gz \
 && /usr/local/bin/opengrep-core -version \
 && /usr/local/bin/trivy --version \
 && /usr/local/bin/syft version
COPY toolchain.lock.json /opt/aegisai/toolchain.lock.json
COPY rules /opt/aegisai/rules
ENV HOME=/tmp GOMAXPROCS=1 SYFT_CHECK_FOR_APP_UPDATE=false SEMGREP_SEND_METRICS=off
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/opengrep-core"]
