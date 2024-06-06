And(/^I use previous Pickup ID to provision (?:from|using) (\S+) a certificate to cloudkeystore "(.*)"( setting keystore and provider names)?$/) do |platform, cloudkeystore_type, keystore_provider_names|

  cmd = build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names)

  steps %{Then I try to run `#{cmd}`}
end

And(/^I use previous Pickup ID to provision (?:from|using) (\S+) a certificate to cloudkeystore "(.*)"( setting keystore and provider names)? with (.+)?/) do |platform, cloudkeystore_type, keystore_provider_names, flags|

  cmd = build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, flags)

  steps %{Then I try to run `#{cmd}`}
end

And(/^I use previous Pickup ID and cloud ID to provision again$/) do
  keystore_provider_names = true
  flags = ""
  if @cloudkeystore_type == $keystore_type_aws
    flags +=  " -arn #{@cloud_id}"
  elsif @cloudkeystore_type == $keystore_type_azure or @cloudkeystore_type == $keystore_type_gcp
    flags +=  " -certificate-name #{@cloud_id}"
  end
  flags += @global_set_provision_flags
  cmd = build_provision_cmd($platform_vcp, @cloudkeystore_type, keystore_provider_names, flags)
  steps %{Then I try to run `#{cmd}`}
end

def build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, flags = "")

  @global_set_provision_flags = flags

  platform_flag = " -platform " + platform

  cmd = "vcert provision cloudkeystore #{platform_flag} #{ENDPOINTS[$platform_vcp]} -pickup-id #{@pickup_id}"

  keystore_name = ""
  provider_name = ""
  keystore_id = ""
  case cloudkeystore_type
  when $keystore_type_aws
    if keystore_provider_names
      keystore_name = $aws_keystore_name
      provider_name = $aws_provider_name
      @cloudkeystore_type = $keystore_type_aws
    else
      keystore_name = $aws_keystore_id
    end
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

Then(/^I grab cloud ID from( JSON)? output$/) do |json|

  @cloud_id = get_cloud_id_from_output(json)

end

def get_cloud_id_from_output(json = false)
  if @previous_command_output.nil?
    fail(ArgumentError.new('@previous_command_output is nil'))
  end

  Kernel.puts("Checking output:\n"+@previous_command_output)
  cloud_id_attr = "cloudId"

  if json
    json_string = extract_json_from_output(@previous_command_output)
    JSON.parse(json_string)
    cloud_id = unescape_text(normalize_json(json_string, "#{cloud_id_attr}")).tr('"', '')
  else
    m = @previous_command_output.match /#{cloud_id_attr}: (.+)$/
    cloud_id = m[1]
  end
  cloud_id
end

Then(/^the output( in JSON)? should contain the previous cloud ID$/) do |json|
  old_cloud_id = @cloud_id
  new_cloud_id = get_cloud_id_from_output(json)
  if old_cloud_id != new_cloud_id
    cleanup_keystore(old_cloud_id)
    cleanup_keystore(new_cloud_id)
    fail(ArgumentError.new("Expected old Cloud ID: #{old_cloud_id} to be same as new Cloud ID, but got: #{new_cloud_id}"))
  end
end

And(/^I clean up previous installed certificate from cloudkeystore/) do ||
  cleanup_keystore
end

def cleanup_keystore(cloud_id = "")
  case @cloudkeystore_type
  when $keystore_type_aws
    cleanup_aws(cloud_id)
  when $keystore_type_azure
  when $keystore_type_gcp
    cleanup_google(cloud_id)
  else
    fail(ArgumentError.new("Unexpected : #{@cloudkeystore_type}"))
  end
end

def cleanup_google(cloud_id = "")
  client = create_google_certificate_manager_client
  if cloud_id != ""
    certificate_name = "projects/#{ENV['GCP_PROJECT']}/locations/#{ENV['GCP_REGION']}/certificates/#{cloud_id}"
  else
    certificate_name = "projects/#{ENV['GCP_PROJECT']}/locations/#{ENV['GCP_REGION']}/certificates/#{@cloud_id}"
  end

  delete_gcm_certificate(client, certificate_name)
end

def cleanup_aws(cloud_id = "")
  client = create_aws_certificate_manager_client
  if cloud_id != ""
    certificate_arn = cloud_id
  else
    certificate_arn = @cloud_id
  end

  delete_acm_certificate(client, certificate_arn)
end
