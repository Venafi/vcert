
When(/^I try to run `([^`]*)`$/)do |cmd|
  puts cmd
  steps %{
    Then I run `#{cmd}`
  }
  if last_command_started.exit_status.to_i != 0
    puts last_command_started.output.to_s
  end
end

When(/^I enroll(?: a)?( random)? certificate (and_random_instance )?(?:in|from|using) (\S+) with (.+)?$/) do |random, random_instance, endpoint, flags|
  if random
    cn = " -cn " + random_cn
  end

  if random_instance
    instance = "-instance devops-instance:" + random_string
  end
  cmd = "vcert enroll #{ENDPOINTS[endpoint]} #{cn} #{flags} #{instance}"
  steps %{Then I try to run `#{cmd}`}

  m = last_command_started.output.match /^PickupID="(.+)"$/
  if m
    @pickup_id = m[1]
  end
end

#I retreive the certificate from TPP using the same PickupID interactively
When(/^I interactively retrieve(?: the) certificate (?:in|from|using) (\S+) using (the same Pickup ID)(?: with)?(.+)?$/) do |endpoint, same_pickup_id, flags|
  cmd = "vcert pickup #{ENDPOINTS[endpoint]} -pickup-id '#{@pickup_id}'#{flags}"
  steps %{Then I try to run `#{cmd}` interactively}
end

#I retreive the certificate from TPP using the same PickupID
When(/^I retrieve(?: the) certificate (?:in|from|using) (\S+) using (the same Pickup ID)(?: with)?(.+)?$/) do |endpoint, same_pickup_id, flags|
  cmd = "vcert pickup #{ENDPOINTS[endpoint]} -pickup-id '#{@pickup_id}'#{flags}"
  steps %{Then I try to run `#{cmd}`}
end

When(/^I retrieve(?: the) certificate (?:from|in|using) (\S+) with (.+)$/) do |endpoint, flags|
  cmd = "vcert pickup #{ENDPOINTS[endpoint]} #{flags}"
  steps %{Then I try to run `#{cmd}`}
end

When(/^I revoke(?: the)? certificate (?:from|in|using) (\S+)(?: using)?( the same Pickup ID)?(?: with)?(.+)?$/) do |endpoint, same_pickup_id, flags|
  if same_pickup_id
    id_value = " -id '#{@pickup_id}'"
  end
  cmd = "vcert revoke #{ENDPOINTS[endpoint]}#{id_value}#{flags}"
  steps %{Then I try to run `#{cmd}`}
end

# renewal via flags, no magic
When(/^I renew(?: the)? certificate (?:from|in|using) (\S+) with(?: flags)?(.+)$/) do |endpoint, flags|
  cmd = "vcert renew #{ENDPOINTS[endpoint]}#{flags}"
  steps %{Then I try to run `#{cmd}`}
end

# renewal via memorized PickupId or thumbprint
When(/^I renew(?: the)? certificate (?:from|in|using) (\S+) using the same (Pickup ID|Thumbprint)(?: with)?(?: flags)?(.+)?$/) do |endpoint, field, flags|
  if field == "Pickup ID"
    cmd = "vcert renew #{ENDPOINTS[endpoint]} -id '#{@pickup_id}' #{flags}"
  end
  if field == "Thumbprint"
    cmd = "vcert renew #{ENDPOINTS[endpoint]} -thumbprint '#{@certificate_fingerprint}' #{flags}"
  end
  steps %{Then I try to run `#{cmd}`}
end

When(/^I generate( random)? CSR(?: with)?(.+)?$/) do |random, flags|
  if random
    cn = " -cn " + random_cn
  end
  cmd = "vcert gencsr#{cn}#{flags}"
  steps %{Then I try to run `#{cmd}`}
end

# Getting credentials
When(/^I( interactively)? get credentials from TPP(?: with)?(.+)?$/) do |interactively, flags|
  if flags === " PKSC12"
    if "#{ENV['PKCS12_FILE']}" === ""
      puts "No PKCS12 file was specified. Skipping scenario"
      skip_this_scenario
    else
      cmd = "vcert getcred -u '#{ENV['TPP_MTLS_URL']}' -p12-file '#{ENV['PKCS12_FILE']}' -p12-password "+
          "'#{ENV['PKCS12_FILE_PASSWORD']}' -trust-bundle '#{ENV['MTLS_TRUST_BUNDLE']}'"
    end
  elsif flags === " PKSC12 and no password"
    if "#{ENV['PKCS12_FILE']}" === ""
      puts "No PKCS12 file was specified. Skipping scenario"
      skip_this_scenario
    else
      cmd = "vcert getcred -u '#{ENV['TPP_URL']}' -p12-file '#{ENV['PKCS12_FILE']}' -p12-password "+
          "'#{ENV['PKCS12_FILE_PASSWORD']}'"
    end
  elsif flags === " username and no password"
    cmd = "vcert getcred -u '#{ENV['TPP_URL']}' -username '#{ENV['TPP_USER']}' -insecure"
  else
    cmd = "vcert getcred -u '#{ENV['TPP_URL']}' -username '#{ENV['TPP_USER']}'" +
        " -password '#{ENV['TPP_PASSWORD']}' #{flags} -insecure"
  end

  if interactively
    puts cmd
    steps %{
      Then I run `#{cmd}` interactively
      And I type "#{ENV['TPP_PASSWORD']}"
      Then the exit status should be 0
    }
  else
    steps %{
    Then I try to run `#{cmd}`
  }
  end
end

When(/^I refresh access token$/) do
  cmd = "vcert getcred -u '#{ENV['TPP_URL']}' -t #{@refresh_token} -insecure"
  steps %{
    Then I try to run `#{cmd}`
      And I remember the output
      And it should output access token
      And it should output refresh token
  }
end