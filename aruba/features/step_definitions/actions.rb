
When(/^I try to run `([^`]*)`$/)do |cmd|
  puts cmd
  steps %{
    Then I run `#{cmd}`
  }
  if last_command_started.exit_status.to_i != 0
    puts last_command_started.output.to_s
  end
end

When(/^I enroll(?: a)?( random)? certificate (?:in|from|using) (\S+) with (.+)?$/) do |random, endpoint, flags|
  if random
    cn = " -cn " + random_cn
  end
  cmd = "vcert enroll #{ENDPOINTS[endpoint]} #{cn} #{flags}"
  steps %{Then I try to run `#{cmd}`}

  m = last_command_started.output.match /^PickupID="(.+)"$/
  if m
    @pickup_id = m[1]
  end
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