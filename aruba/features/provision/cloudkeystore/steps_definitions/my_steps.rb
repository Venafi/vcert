And(/^I use previous Pickup ID to provision (?:from|using) (\S+) a certificate to cloudkeystore "(.*)"( setting keystore and provider names)?$/) do |platform, cloudkeystore_type, keystore_provider_names|

  cmd = build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, "",true)

  steps %{Then I try to run `#{cmd}`}
end

And(/^I use previous Pickup ID to provision without set Platform flag (?:from|using) (\S+) a certificate to cloudkeystore "(.*)"( setting keystore and provider names)?$/) do |platform, cloudkeystore_type, keystore_provider_names|

  cmd = build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, "",false)

  steps %{Then I try to run `#{cmd}`}
end

And(/^I use previous Pickup ID to provision (?:from|using) (\S+) a certificate to cloudkeystore "(.*)"( setting keystore and provider names)? with (.+)?/) do |platform, cloudkeystore_type, keystore_provider_names, flags|

  cmd = build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, flags, true)

  steps %{Then I try to run `#{cmd}`}
end

And(/^I use previous Pickup ID and cloud ID to provision again$/) do
  keystore_provider_names = true
  flags = ""
  case @cloudkeystore_type
  when KEYSTORE_TYPE_AWS
    flags +=  " -arn #{@cloud_id}"
  when KEYSTORE_TYPE_AZURE
    flags +=  " -certificate-name #{@cloud_name}"
  when KEYSTORE_TYPE_GCP
      flags +=  " -certificate-name #{@cloud_id}"
  else
    fail(ArgumentError.new("Unknown cloud type: #{@cloudkeystore_type}"))
  end
  flags += @global_set_provision_flags
  cmd = build_provision_cmd(PLATFORM_VCP, @cloudkeystore_type, keystore_provider_names, flags, true)
  steps %{Then I try to run `#{cmd}`}
end

def build_provision_cmd(platform, cloudkeystore_type, keystore_provider_names, flags = "", set_platform_flag=true)

  @global_set_provision_flags = flags

  cmd = "vcert provision cloudkeystore #{ENDPOINTS[PLATFORM_VCP]} -pickup-id #{@pickup_id}"

  if set_platform_flag
    platform_flag = " -platform " + platform
    cmd = cmd + platform_flag
  end

  keystore_name = ""
  provider_name = ""
  keystore_id = ""
  case cloudkeystore_type
  when KEYSTORE_TYPE_AWS
    @cloudkeystore_type = KEYSTORE_TYPE_AWS
    if keystore_provider_names
      keystore_name = AWS_KEYSTORE_NAME
      provider_name = AWS_PROVIDER_NAME

    else
      keystore_id = AWS_KEYSTORE_ID
    end
  when KEYSTORE_TYPE_AZURE
    @cloudkeystore_type = KEYSTORE_TYPE_AZURE
    if keystore_provider_names
      keystore_name = AZURE_KEYSTORE_NAME
      provider_name = AZURE_PROVIDER_NAME
    else
      keystore_id = AZURE_KEYSTORE_ID
    end
  when KEYSTORE_TYPE_GCP
    @cloudkeystore_type = KEYSTORE_TYPE_GCP
    if keystore_provider_names
      keystore_name = GCP_KEYSTORE_NAME
      provider_name = GCP_PROVIDER_NAME
    else
      keystore_id = GCP_KEYSTORE_ID
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

  @cloud_id = get_value_from_output("cloudId",json)
  if @cloudkeystore_type == KEYSTORE_TYPE_AZURE
    @cloud_name = get_value_from_output("azureName",json)
  end
end

def get_value_from_output(value, json = false)
  if @previous_command_output.nil?
    fail(ArgumentError.new('@previous_command_output is nil'))
  end

  Kernel.puts("Checking output:\n"+@previous_command_output)

  if json
    json_string = extract_json_from_output(@previous_command_output)
    JSON.parse(json_string)
    extracted_val = unescape_text(normalize_json(json_string, "#{value}")).tr('"', '')
  else
    m = @previous_command_output.match /#{value}: (.+)$/
    extracted_val = m[1]
  end
  extracted_val
end

Then(/^the output( in JSON)? should contain the previous cloud ID$/) do |json|
  validate_provision_replace(json)
end

def validate_provision_replace(json)
  # for azure case we want to check the name instead
  if @cloudkeystore_type == KEYSTORE_TYPE_AZURE
    old_cloud_name = @cloud_name
    new_cloud_name = get_value_from_output("azureName", json)
    if old_cloud_name != new_cloud_name
      cleanup_keystore(old_cloud_name)
      cleanup_keystore(new_cloud_name)
      fail(ArgumentError.new("Expected old Cloud Name: #{old_cloud_name} to be same as new Cloud Name, but got: #{new_cloud_name}"))
    end
    return
  end
  old_cloud_id = @cloud_id
  new_cloud_id = get_value_from_output("cloudId", json)
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
  when KEYSTORE_TYPE_AWS
    cleanup_aws(cloud_id)
  when KEYSTORE_TYPE_AZURE
    cleanup_akv(@cloud_name)
  when KEYSTORE_TYPE_GCP
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

def cleanup_akv(cloud_name = "")
  if cloud_name != ""
    certificate_name = cloud_name
  else
    certificate_name = @cloud_name
  end

  delete_azure_certificate(certificate_name)
end
