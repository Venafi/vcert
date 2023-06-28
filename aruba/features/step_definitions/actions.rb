
When(/^I try to run `([^`]*)`$/)do |cmd|
  Kernel.puts cmd
  steps %{
    Then I run `#{cmd}`
  }
  if last_command_started.exit_status.to_i != 0
    Kernel.puts last_command_started.output.to_s
  end
end

When(/^I enroll(?: a)?( random)? certificate (and_random_instance )?(?:in|from|using) (\S+) with (.+)?$/) do |random, random_instance, endpoint, flags|
  if random
    cn = " -cn " + random_cn
  end

  if random_instance
    instance = "-instance devops-instance:" + random_string
  end
  cmd = "vcert enroll #{ENDPOINTS[endpoint]} #{ZONE[endpoint]} #{cn} #{flags} #{instance}"
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

# retire via PickupId
When(/^I retire(?: the)? certificate (?:from|in|using) (\S+)(?: using)?( the same Pickup ID)?(?: with)?(.+)?$/) do |endpoint, same_pickup_id|
  if same_pickup_id
    id_value = " -id '#{@pickup_id}'"
  end
  cmd = "vcert retire #{ENDPOINTS[endpoint]}#{id_value}"
  steps %{Then I try to run `#{cmd}`}
end

# renewal via flags, no magic
When(/^I renew(?: the)? certificate (?:from|in|using) (\S+) with(?: flags)?(.+)$/) do |endpoint, flags|
  sleep 2
  cmd = "vcert renew #{ENDPOINTS[endpoint]}#{flags}"
  steps %{Then I try to run `#{cmd}`}
end

# renewal via memorized PickupId or thumbprint
When(/^I renew(?: the)? certificate (?:from|in|using) (\S+) using the same (Pickup ID|Thumbprint)(?: with)?(?: flags)?(.+)?$/) do |endpoint, field, flags|
  sleep 2
  if field == "Pickup ID"
    cmd = "vcert renew #{ENDPOINTS[endpoint]} -id '#{@pickup_id}' #{flags}"
  end
  if field == "Thumbprint"
    cmd = "vcert renew #{ENDPOINTS[endpoint]} -thumbprint '#{@certificate_fingerprint}' #{flags}"
  end
  if flags != ""
    # we try to get key-password
    # This regex basically tries to get everything after and including "-key-password " (note the space in the string)
    # stops until it finds either (a whitespace character and a dash) or (end of line)
    # without including it
    # TODO: this can be improved by adding every flag known for the action using a regex like the following:
    # /-key-password .+?(?= \-key\-file| \-cert\-file)/gm
    # where can be translated to:
    # /key_in_flags .+?(?= flag1| flag2 | flag3|... flagN|$)/gm
    keypass = flags[/-key-password .+?(?=\s-|$)/]
    # For example, the following value:
    # flags = "-cert-file c1.pem -key-file k1.pem -csr service -key-password"
    # Won't enter the following "if" statement.
    # In general, if there's no match then variable keypass will be undefined
    if keypass
        # if it does exist, we split it to try to get the keypassword (default delimiter is whitspace)
        keypass_split = keypass.split
        # If we get an empty string like the following example:
        # flags = "-cert-file c1.pem -key-file k1.pem -csr service -key-password -new pass"
        # then, keypass_split[1] will be null
        if keypass_split[1]
            @key_password = keypass_split[1]
        end
    end
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
      Kernel.puts "No PKCS12 file was specified. Skipping scenario"
      skip_this_scenario
    else
      cmd = "vcert getcred -u '#{ENV['TPP_MTLS_URL']}' -p12-file '#{ENV['PKCS12_FILE']}' -p12-password "+
          "'#{ENV['PKCS12_FILE_PASSWORD']}' -trust-bundle '#{ENV['MTLS_TRUST_BUNDLE']}'"
    end
  elsif flags === " PKSC12 and no password"
    if "#{ENV['PKCS12_FILE']}" === ""
      Kernel.puts "No PKCS12 file was specified. Skipping scenario"
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
    Kernel.puts cmd
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

When(/^I check access token(?: with)?(.+)?$/) do |flags|
  cmd = "vcert checkcred -u '#{ENV['TPP_URL']}' -t #{@access_token} #{flags} -insecure"
  steps %{
    Then I try to run `#{cmd}`
  }
end

When(/^I void access token grant$/) do
  cmd = "vcert voidcred -u '#{ENV['TPP_URL']}' -t #{@access_token} -insecure"
  steps %{
    Then I try to run `#{cmd}`
  }
end

Before('@TODO') do  # will only run if the test has @TODO annotation
  skip_this_scenario
end
