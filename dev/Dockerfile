FROM centos:7

ARG GO_VERSION=1.14.4

RUN yum install -y make wget gcc glibc-static
RUN yum install --assumeyes softhsm

RUN wget https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz \
  && sha256sum go${GO_VERSION}.linux-amd64.tar.gz \
  && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/tmp

