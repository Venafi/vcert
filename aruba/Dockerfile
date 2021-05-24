FROM ruby
MAINTAINER Venafi DevOps Integrations <opensource@venafi.com>

RUN gem install aruba json_spec
COPY . /vcert/
ENV PATH="/vcert/bin:${PATH}"

WORKDIR /vcert/
#ENTRYPOINT ["sh", "-c", "echo ${TPP_IP} ${TPP_CN} >> /etc/hosts && cat /etc/hosts && echo $FILE_PATH && cucumber --fail-fast --no-color -v $FILE_PATH"]
ENTRYPOINT ["sh", "-c", "echo ${TPP_IP} ${TPP_CN} >> /etc/hosts && cucumber --fail-fast --no-color -v $FILE_PATH"]
