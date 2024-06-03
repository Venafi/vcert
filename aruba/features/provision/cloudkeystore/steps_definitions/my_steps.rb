And(/^I use previous Pickup ID to provision (?:from|using) (\S+) a certificate to cloudkeystore "(.*)"( setting keystore and provider names)?$/) do |platform, cloudkeystore_type, keystore_provider_names|

  cmd = build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names)

  steps %{Then I try to run `#{cmd}`}
end

And(/^I use previous Pickup ID to provision (?:from|using) (\S+) a certificate to cloudkeystore "(.*)"( setting keystore and provider names)? with (.+)?/) do |platform, cloudkeystore_type, keystore_provider_names, flags|

  cmd = build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, flags)

  steps %{Then I try to run `#{cmd}`}
end

def build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, flags = "")

  platform_flag = " -platform " + platform

  cmd = "vcert provision cloudkeystore #{platform_flag} #{ENDPOINTS[$platform_vcp]} -pickup-id #{@pickup_id}"

  keystore_name = ""
  provider_name = ""
  keystore_id = ""
  case cloudkeystore_type
  when $keystore_type_azure
  when $keystore_type_gcp
    if keystore_provider_names
      keystore_name = $gcp_keystore_name
      provider_name = $gcp_provider_name
      @cloudkeystore_type = $keystore_type_gcp
    else
      keystore_id = $gcp_keystore_id
    end
  else
    fail(ArgumentError.new("Unexpected : #{cloudkeystore_type}"))
  end
  if keystore_provider_names
    keystore_name_flag = " -keystore-name '#{keystore_name}'"
    provider_name_flag = " -provider-name '#{provider_name}'"

    cmd = "#{cmd} #{keystore_name_flag} #{provider_name_flag}"
  else
    keystore_id_flag = " -keystore-id " + keystore_id
    cmd = "#{cmd} #{keystore_id_flag}"
  end

  if flags != ""
    cmd += " #{flags}"
  end

  return cmd
end

Then(/^it should output keystore ID( in JSON)?$/) do |json|

  if @previous_command_output.nil?
    fail(ArgumentError.new('@previous_command_output is nil'))
  end

  Kernel.puts("Checking output:\n"+@previous_command_output)
  keystore_id = ""
  case @cloudkeystore_type
  when $keystore_type_aws
  when $keystore_type_azure
  when $keystore_type_gcp
        keystore_id = "gcpId"
  else
    fail(ArgumentError.new("Unexpected : #{@cloudkeystore_type}"))
  end
  if json
    json_string = extract_json_from_output(@previous_command_output)
    JSON.parse(json_string)
    @keystore_id = unescape_text(normalize_json(json_string, "#{keystore_id}")).tr('"', '')
  else
    m = @previous_command_output.match /#{keystore_id} (.+)$/
    @keystore_id = m[1]
  end
end

And(/^I clean up previous installed certificate from cloudkeystore/) do ||
  case @cloudkeystore_type
  when $keystore_type_aws
  when $keystore_type_azure
  when $keystore_type_gcp
    cleanup_google
  else
    fail(ArgumentError.new("Unexpected : #{@cloudkeystore_type}"))
  end
end

def cleanup_google
  client = create_certificate_manager_client
  certificate_name = "projects/#{ENV['GCP_PROJECT']}/locations/#{ENV['GCP_REGION']}/certificates/#{@keystore_id}"
  delete_certificate(client, certificate_name)
end
