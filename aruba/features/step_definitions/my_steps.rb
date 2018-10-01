
Then(/^it should retrieve certificate$/) do
  steps %{
    Given the exit status should be 0
    And the output should contain "Successfully retrieved request for"
  }
end

Then(/^it should post certificate request$/) do
  steps %{
    Then the exit status should be 0
    And the output should contain "Successfully posted request for"
  }
end

Then(/^it should( not)? output( encrypted)? private key$/) do |negated, encrypted|
  steps %{Then the output should#{negated} contain "-----BEGIN RSA PRIVATE KEY-----"}
  if encrypted
    steps %{Then the output should#{negated} contain "ENCRYPTED"}
  end
end

And(/^it should( not)? output Pickup ID$/) do |negated|
  steps %{Then the output should#{negated} match /^PickupID=".+"$/}
  unless negated
    m = last_command_started.output.match /^PickupID="(.+)"$/
    @pickup_id = m[1]
  end
end

When(/^it should write Pickup ID to (?:a|the) file(?: named)? "([^"]*)"$/) do |filename|
  steps %{Then the file named "#{filename}" should exist}
end

When(/^it should write( encrypted)? private key to (?:a|the) file(?: named)? "([^"]*)"$/) do |encrypted, filename|
  steps %{Then the file named "#{filename}" should exist}
  if encrypted
    steps %{Then the file named "#{filename}" should contain "ENCRYPTED"}
  end
end

And(/^show output$/) do
  puts last_command_started.output.to_s
end

And(/^it should( not)? output CSR$/) do |negated|
  steps %{
    Then the exit status should be 0
    And the output should#{negated} contain "-----BEGIN CERTIFICATE REQUEST-----"
  }
end

And(/^it should( not)? write CSR to the file(?: named)? "(.+)"$/) do |negated, filename|
  steps %{
    Then the exit status should be 0
    And the file named "#{filename}" should#{negated} exist
  }
end

And(/^it should( not)? write certificate to the file(?: named)? "(.+)"$/) do |negated, filename|
  steps %{
    Then the exit status should be 0
    And the file named "#{filename}" should#{negated} exist
  }
end

And(/^I remember the output$/) do
  @previous_command_output = last_command_started.output.to_s
end

When(/^the outputs should( not)? be the same$/) do |negated|
  if negated
    expect(last_command_started.output.to_s).not_to send(:an_output_string_being_eq,  @previous_command_output)
  else
    expect(last_command_started.output.to_s).to send(:an_output_string_being_eq,  @previous_command_output)
  end
end

