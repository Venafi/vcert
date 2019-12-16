FROM ruby
MAINTAINER Venafi DevOps Integrations <opensource@venafi.com>

RUN gem install aruba json_spec
COPY . /vcert/
ENV PATH="/vcert/bin:${PATH}"

WORKDIR /vcert/
CMD ["cucumber", "--no-color"]


