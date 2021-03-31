FROM ruby
MAINTAINER Venafi DevOps Integrations <opensource@venafi.com>

RUN gem install aruba json_spec
COPY . /vcert/
ENV PATH="/vcert/bin:${PATH}"

WORKDIR /vcert/
ENTRYPOINT echo "${TPP_IP} ${TPP_CN}" >> /etc/hosts && cucumber --no-color


