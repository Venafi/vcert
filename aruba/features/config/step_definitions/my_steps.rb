

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