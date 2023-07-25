

When(/^I have file named "([^"]*)" with (\S+) connection details$/) do |fname, endpoint|

  steps %{
          Then a file named "#{fname}" with:
          """
          #{ENDPOINT_CONFIGS[endpoint]}
          """
        }
end

When(/^I have file named "([^"]*)" with all endpoints connection details$/) do |fname|

  steps %{
          Then a file named "#{fname}" with:
          """
          #{ALL_ENDPOINTS_CONFIG}
          """
        }
end

When(/^I enroll random certificate \-config "([^"]*)" \-profile (.*) with (.+)?$/) do |config, profile, flags|
  cn = " -cn " + random_cn
  cmd = "vcert enroll -config #{config} -profile #{profile} #{cn} #{flags}"

  steps %{Then I try to run `#{cmd}`}
end