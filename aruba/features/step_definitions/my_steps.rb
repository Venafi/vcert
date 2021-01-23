Then(/^it should show deprecated warning$/) do
  steps %{
    Given the exit status should be 0
    And the output should contain "Password authentication is deprecated"
  }
end

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
  Kernel.puts last_command_started.output.to_s
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
    expect(last_command_started.output.to_s).not_to send(:an_output_string_being_eq, @previous_command_output)
  else
    expect(last_command_started.output.to_s).to send(:an_output_string_being_eq, @previous_command_output)
  end
end


Then(/^it should( not)? output (access|refresh) token( in JSON)?$/) do |negated, token, json|

  if @previous_command_output.nil?
    fail(ArgumentError.new('@previous_command_output is nil'))
  end

  Kernel.puts("Checking output:\n"+@previous_command_output)
  unless json
    steps %{Then the output should#{negated} contain "access_token:"}
  end

  unless negated
    if json then
      JSON.parse(@previous_command_output)
      if token === "access"
        @access_token = unescape_text(normalize_json(@previous_command_output, "access_token")).tr('"', '')
      elsif token === "refresh"
        @refresh_token = unescape_text(normalize_json(@previous_command_output, "refresh_token")).tr('"', '')
      else
        fail(ArgumentError.new("Cant determine token type for #{token}"))
      end
    else
      if token === "access"
        m = @previous_command_output.match /access_token:  (.+)$/
        @access_token = m[1]
      elsif token === "refresh"
        m = @previous_command_output.match /^refresh_token:  (.+)$/
        @refresh_token = m[1]
      else
        fail(ArgumentError.new("Cant determine token type for #{token}"))
      end
    end
  end
end

Then(/^it should( not)? output (application|expires|scope)( in JSON)?$/) do |negated, property, json|

  if @previous_command_output.nil?
    fail(ArgumentError.new('@previous_command_output is nil'))
  end

  Kernel.puts("Checking output:\n"+@previous_command_output)
  unless json
    steps %{Then the output should#{negated} contain "access_token:"}
  end

  unless negated
    if json then
      JSON.parse(@previous_command_output)
      if property === "application"
        @application = unescape_text(normalize_json(@previous_command_output, "application")).tr('"', '')
      elsif property === "expires"
        @expires = unescape_text(normalize_json(@previous_command_output, "expires_ISO8601")).tr('"', '')
      elsif property === "scope"
        @scope = unescape_text(normalize_json(@previous_command_output, "scope")).tr('"', '')
      else
        fail(ArgumentError.new("Cant determine property type for #{property}"))
      end
    else
      if property === "application"
        m = @previous_command_output.match /^client_id:  (.+)$/
        @application = m[1]
      elsif property === "expires"
        m = @previous_command_output.match /^access_token_expires:  (.+)$/
        @expires = m[1]
      elsif property === "scope"
        m = @previous_command_output.match /^scope:  (.+)$/
        @scope = m[1]
      else
        fail(ArgumentError.new("Cant determine property type for #{property}"))
      end
    end
  end
end

Then(/^it should( not)? output revoked$/) do |negated|
  steps %{Then the output should#{negated} contain "access token successfully revoked"}
end
