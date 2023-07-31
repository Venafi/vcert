require 'yaml'

Given(/^I have playbook with (\S+) connection details$/) do |platform|

  @playbook_data = {
    config: {
      connection: nil
    }
  }

  if platform == "TPP"
    connection_tpp = {
      type: "tpp",
      url: ENV['TPP_URL'],
      trustBundle: ENV['TPP_TRUST_BUNDLE']
    }
    credentials = {
      clientId: "vcert-sdk",
      accessToken: ENV['TPP_ACCESS_TOKEN']
    }
    connection_tpp['credentials'] = credentials
    @playbook_data[:config][:connection] = connection_tpp
  elsif platform == "VaaS"
    connection_vaas = {
      type: "vaas"
    }
    credentials = {
      clientId: "vcert-sdk",
      accessToken: ENV['CLOUD_APIKEY']
    }
    connection_vaas['credentials'] = credentials
    @playbook_data['config']['connection'] = connection_vaas
  end
end

And(/^I append file named "(.*)" with certificates block$/) do |fname|
  steps %{
    Then I append to "#{fname}" with:
    """
    certificates:
    """
  }
end

And(/^I append file named "(.*)" with task named "(.*)"$/) do |fname, task_name|
  steps %{
    Then I append to "#{fname}" with:
    """
    - name: #{task_name}
    """
  }
end

And(/^I append file named "(.*)" with random common name$/) do |fname|
  cn = random_cn
  steps %{
    Then I append to "#{fname}" with:
    """
    commonName: #{cn}
    """
  }
end

And(/^I append file named "(.*)" and "(.*)" connection details with zone$/) do |fname, platform|
  zone=""
  if platform == "VaaS"
    zone=ENV['CLOUD_ZONE']
  elsif platform == "TPP"
    zone=ENV['TPP_ZONE']
  end
  steps %{
    Then I append to "#{fname}" with:
    """
    zone: #{zone}
    """
  }
end

And(/^I append file named "(.*)" with installations block$/) do |fname|
  steps %{
    Then I append to "#{fname}" with:
    """
    installations:
    """
  }
end

And(/^I append file named "(.*)" with installation type PEM with cert name "(.*)", chain name "(.*)" and key name "(.*)"(?: that uses)( installation script)?$/) do |fname, cert_name, chain_name, key_name, installation|
  installation_block="""
  - type: PEM
      location: '{{- Env \"PWD\" }}'
      pemCertFilename: \"#{cert_name}\"
      pemChainFilename: \"#{chain_name}\"
      pemKeyFilename: \"#{key_name}\"
  """
  if installation
    installation_block=installation+"""
    afterInstallAction: \"echo Success!!!\"
    """
  end
  steps %{
    Then I append to "#{fname}" with:
    """
    #{installation_block}
    """
  }
end

And(/^I append file named "(.*)" with installation type JKS with jksAlias "(.*)" and jksPassword "(.*)"(?: that uses)( installation script)?$/) do |fname, jks_alias, jks_password, installation|
  installation_block="""
  - type: JKS
      location: '{{- Env \"PWD\" }}'
      jksAlias: \"#{jks_alias}\"
      jksPassword: \"#{jks_password}\"
  """
  if installation
    installation_block=installation+"""
    afterInstallAction: \"echo Success!!!\"
    """
  end
  steps %{
    Then I append to "#{fname}" with:
    """
    #{installation_block}
    """
  }
end

And(/^I append file named "(.*)" with installation type PKCS12(?: that uses)( installation script)?$/) do |fname, installation|
  installation_block="""
  - type: PKCS12
      location: '{{- Env \"PWD\" }}'
  """
  if installation
    installation_block=installation+"""
    afterInstallAction: \"echo Success!!!\"
    """
  end
  steps %{
    Then I append to "#{fname}" with:
    """
    #{installation_block}
    """
  }
end

Then(/^I created playbook named "(.*)" with previous content$/) do |fname|
  stringified_data = stringify_keys(@playbook_data)
  File.write(fname, stringified_data.to_yaml)
end

And(/^I have playbook with certificates block$/) do
  @playbook_data['certificates'] = Array.new
end

And(/^I have playbook with task named "(.*)"$/) do |task_name|
  aux_playbook_task = PlaybookTask.new()
  aux_playbook_task.name = task_name
  # @playbook_data['certificates'].push(object_to_hash(aux_playbook_task))
  @playbook_data['certificates'].push(aux_playbook_task)
end

And(/^task named "(.*)" has request$/) do |task_name|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.request = Request.new
end

And(/^task named "(.*)" has request with "(.*)" value "(.*)"$/) do |task_name, key, value|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }

  if request_key_should_be_string(key)
    if value.is_a?(String)
      current_certificate_task.request.send "#{key}=", value
    else
      fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected a String but got: #{value.class}"))
    end
  elsif request_key_should_be_integer(key)
    value_int = to_integer(key, value)
    current_certificate_task.request.send "#{key}=", value_int
  elsif request_key_should_be_boolean(key)
    value_bool = to_boolean(key, value)
    current_certificate_task.request.send "#{key}=", value_bool
  elsif request_key_should_be_array_of_strings(key)
    array_string = value.split(',')
    if array_string.all? { |elem_value|
      unless elem_value.is_a?(String)
        fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected an Array if strings but got value in array that is: #{elem_value.class}"))
      end
    }
    current_certificate_task.request.send "#{key}=", array_string
    end
      # fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected an Array but got: #{value.class}"))

  elsif key == "location"
    fail(ArgumentError.new("request key: #{key} should be defined with regex: \"task name <name> has request with Location instance\""))
  elsif key == "subject"
    fail(ArgumentError.new("request key: #{key} should be defined with regex: \"task name <name> request has subject with: <key> value <value>\""))
  else
    fail(ArgumentError.new("type of value #{value.to_s} is not valid for request key: #{key}"))
  end
end

And(/^task named "(.*)" has request with default "(.*)" zone$/) do |task_name, platform|
  pending
end