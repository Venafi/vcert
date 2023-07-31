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

Then(/^I created playbook named "(.*)" with previous content$/) do |fname|
  new_data = object_to_hash(@playbook_data)
  stringified_data = stringify_keys(new_data)
  path_name="tmp/aruba/#{fname}"
  File.write(path_name, stringified_data.to_yaml)
end

And(/^I have playbook with certificates block$/) do
  @playbook_data['certificates'] = Array.new
end

And(/^I have playbook with task named "(.*)"$/) do |task_name|
  aux_playbook_task = PlaybookTask.new()
  aux_playbook_task.name = task_name
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
    value_bool = to_boolean_kv(key, value)
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
  elsif key == "location"
    fail(ArgumentError.new("request key: #{key} should be defined with regex: \"task name <name> has request with Location instance\""))
  elsif key == "subject"
    fail(ArgumentError.new("request key: #{key} should be defined with regex: \"task name <name> request has subject with: <key> value <value>\""))
  else
    fail(ArgumentError.new("type of value #{value.to_s} is not valid for request key: #{key}"))
  end
end

And(/^task named "(.*)" has request with default (.*) zone$/) do |task_name, platform|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  if platform == "TPP"
    current_certificate_task.request.zone=ENV['TPP_ZONE']
  elsif platform == "VaaS"
    current_certificate_task.request.zone=ENV['CLOUD_ZONE']
  else
      fail(ArgumentError.new("Unkonw plataform: #{platform}"))
  end
end

And(/^task named "(.*)" has request with Location instance "(.*)", workload prefixed by "(.*)", tlsAddress "(.*)" and replace "(.*)"$/) do |task_name, instance, workload_prefix, tls_address, replace|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.request.location = Location.new
  workload = "#{workload_prefix}-#{Time.now.to_i.to_s}"

  instance_name = "#{instance}:#{workload}"
  current_certificate_task.request.location.instance = instance_name
  current_certificate_task.request.location.tlsAddress = tls_address
  current_certificate_task.request.location.replace = to_boolean(replace)
end

And(/^task named "(.*)" request has subject$/) do |task_name|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.request.subject = Subject.new
end

And(/^task named "(.*)" request has subject with "(.*)" value "(.*)"$/) do |task_name, key, value|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  if request_subject_key_should_be_string(key)
    if value.is_a?(String)
      current_certificate_task.request.subject.send "#{key}=", value
    else
      fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected a String but got: #{value.class}"))
    end
  elsif request_subject_key_should_be_array_of_strings(key)
    array_string = value.split(',')
    if array_string.all? { |elem_value|
      unless elem_value.is_a?(String)
        fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected an Array if strings but got value in array that is: #{elem_value.class}"))
      end
    }
      current_certificate_task.request.subject.send "#{key}=", array_string
    end
  else
    fail(ArgumentError.new("type of value #{value.to_s} is not valid for request subject key: #{key}"))
  end
end

And(/^task named "(.*)" request has subject random CommonName$/) do |task_name|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  cn = random_cn
  current_certificate_task.request.subject.commonName = cn
end

And(/^task named "(.*)" has installations$/) do |task_name|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.installations = Array.new
end

And(/^task named "(.*)" has installation type PEM with cert name "(.*)", chain name "(.*)" and key name "(.*)"(?: that uses)( installation script)?$/) do |task_name, cert_name, chain_name, key_name, installation|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  aux_installation = Installation.new
  aux_installation.type = "PEM"
  aux_installation.location = "{{- Env \"PWD\" }}" + "/tmp/"
  aux_installation.pemCertFilename = cert_name
  aux_installation.pemChainFilename = chain_name
  aux_installation.pemKeyFilename = key_name
  if installation
    aux_installation.afterInstallAction = "echo Success!!!"
  end
  current_certificate_task.installations.push(aux_installation)
end

And(/^task named "(.*)" has installation type JKS with cert name "(.*)", jksAlias "(.*)" and jksPassword "(.*)"(?: that uses)( installation script)?$/) do |task_name, cert_name, jks_alias, jks_password, installation|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  aux_installation = Installation.new
  aux_installation.type = "JKS"
  aux_installation.location = "{{- Env \"PWD\" }}" + "/tmp/#{cert_name}"
  aux_installation.jksAlias = jks_alias
  aux_installation.jksPassword = jks_password
  if installation
    aux_installation.afterInstallAction = "echo Success!!!"
  end
  current_certificate_task.installations.push(aux_installation)
end

And(/^task named "(.*)" has installation type PKCS12 with cert name "(.*)"(?: that uses)( installation script)?$/) do |task_name, cert_name, installation|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  aux_installation = Installation.new
  aux_installation.type = "PKCS12"
  aux_installation.location = "{{- Env \"PWD\" }}" + "/tmp/#{cert_name}"
  if installation
    aux_installation.afterInstallAction = "echo Success!!!"
  end
  current_certificate_task.installations.push(aux_installation)
end

And(/^task named "(.*)" has setenvvars "(.*)"$/) do |task_name, set_env_vars|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.setenvvars = set_env_vars.split(',')
end

And(/^task named "(.*)" has renewBefore with value "(.*)"$/) do |task_name, renew_before|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.renewBefore = renew_before
end

And(/^task named "(.*)" has request with friendlyName based on commonName$/) do |task_name|
  current_certificate_task = @playbook_data['certificates'].find { |certificate_task| certificate_task.name == task_name }
  if current_certificate_task.request == Request.new
    fail(ArgumentError.new("Error while trying to set friendlyName based on commonName: no request defined"))
  end
  if current_certificate_task.request.subject == Subject.new
    fail(ArgumentError.new("Error while trying to set friendlyName based on commonName: no subject defined"))
  end
  if current_certificate_task.request.subject.commonName.nil? or current_certificate_task.request.subject.commonName == ""
    fail(ArgumentError.new("Error while trying to set friendlyName based on commonName: no commonName defined"))
  end
  current_certificate_task.request.friendlyName = "friendly.#{current_certificate_task.request.subject.commonName}"
end