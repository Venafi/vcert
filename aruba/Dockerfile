FROM ruby:3.2
MAINTAINER Venafi DevOps Integrations <opensource@venafi.com>

RUN gem install aruba json_spec
RUN gem install google-cloud-certificate_manager-v1
RUN gem install aws-sdk-acm
COPY . /vcert/
ENV BUNDLE_PATH="/vcert/tpp"
ENV GCP_AUTH_PATH="/vcert/cloud_providers"
RUN mkdir -p $BUNDLE_PATH
RUN mkdir -p $GCP_AUTH_PATH
COPY tpp-bundle.pem $BUNDLE_PATH
COPY google_auth.json $GCP_AUTH_PATH
ENV FIREFLY_BUNDLE_PATH="/vcert/firefly"
RUN mkdir -p $FIREFLY_BUNDLE_PATH
COPY firefly-bundle.pem $FIREFLY_BUNDLE_PATH
ENV PATH="/vcert/bin:${PATH}"

WORKDIR /vcert/
#ENTRYPOINT ["sh", "-c", "echo ${TPP_IP} ${TPP_CN} >> /etc/hosts && cat /etc/hosts && cat ${TPP_TRUST_BUNDLE} && echo $FILE_PATH && cucumber --fail-fast --no-color -v ${FILE_PATH} ${TAGS}"]
ENTRYPOINT ["sh", "-c", "echo ${TPP_IP} ${TPP_CN} >> /etc/hosts && cat /etc/hosts && echo $FILE_PATH && cucumber --no-color -v ${FILE_PATH} ${TAGS}"]
