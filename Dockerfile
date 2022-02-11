FROM golang:latest

ENV SONAR_SCANNER_VERSION="4.6.2.2472"

# Installing sonar-scanner  tool
WORKDIR /root
RUN apt-get update
RUN apt-get install -y wget unzip
RUN wget https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux.zip
RUN unzip sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux.zip
RUN rm sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux.zip
RUN mv ./sonar-scanner-${SONAR_SCANNER_VERSION}-linux ./sonar-scanner
ENV PATH="/root/sonar-scanner/bin:${PATH}"

COPY . /go/src/github.com/Venafi/vcert/v4

WORKDIR /go/src/github.com/Venafi/vcert/v4

CMD ["/bin/bash" ]
