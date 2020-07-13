FROM centos:7

ARG GO_VERSION=1.14.4

RUN yum install -y make wget gcc glibc-static

RUN wget https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz \
  && sha256sum go${GO_VERSION}.linux-amd64.tar.gz \
  && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

RUN mkdir -p /src
COPY ./ /src

RUN \
 PATH=$PATH:/usr/local/go/bin \
 && cd /src \
 && make build  
