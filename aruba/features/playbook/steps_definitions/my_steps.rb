require 'yaml'

Given(/^I have playbook with (\S+) connection details$/) do |platform|

  @playbook_data = {
    config: {
      connection: nil
    }
  }

  if platform == "TPP"
    validate_tpp_envs
    connection_tpp = {
      platform: "tpp",
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
    validate_vaas_envs
    connection_vaas = {
      platform: "vaas"
    }
    credentials = {
      clientId: "vcert-sdk",
      apiKey: ENV['CLOUD_APIKEY']
    }
    connection_vaas['credentials'] = credentials
    @playbook_data[:config][:connection] = connection_vaas
  end
end

Then(/^I created playbook named "(.*)" with previous content$/) do |fname|
  new_data = object_to_hash(@playbook_data)
  stringified_data = stringify_keys(new_data)
  path_name="tmp/aruba/#{fname}"
  File.write(path_name, stringified_data.to_yaml)
end

And(/^I have playbook with certificateTasks block$/) do
  @playbook_data['certificateTasks'] = Array.new
end

And(/^I have playbook with task named "(.*)"$/) do |task_name|
  aux_playbook_task = PlaybookTask.new()
  aux_playbook_task.name = task_name
  @playbook_data['certificateTasks'].push(aux_playbook_task)
end

And(/^task named "(.*)" has request$/) do |task_name|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.request = Request.new
end

And(/^task named "(.*)" has request with "(.*)" value "(.*)"$/) do |task_name, key, value|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }

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
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  if platform == "TPP"
    current_certificate_task.request.zone=ENV['TPP_ZONE']
  elsif platform == "VaaS"
    current_certificate_task.request.zone=ENV['CLOUD_ZONE']
  else
      fail(ArgumentError.new("Unkonw plataform: #{platform}"))
  end
end

And(/^task named "(.*)" has request with Location instance "(.*)", workload prefixed by "(.*)", tlsAddress "(.*)" and replace "(.*)"$/) do |task_name, instance, workload_prefix, tls_address, replace|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.request.location = Location.new
  workload = "#{workload_prefix}-#{Time.now.to_i.to_s}"

  current_certificate_task.request.location.instance = instance
  current_certificate_task.request.location.workload = workload
  current_certificate_task.request.location.tlsAddress = tls_address
  current_certificate_task.request.location.replace = to_boolean(replace)
end

And(/^task named "(.*)" request has subject$/) do |task_name|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.request.subject = Subject.new
end

And(/^task named "(.*)" request has subject with default values$/) do |task_name|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.request.subject.country = "US"
  current_certificate_task.request.subject.locality = "Salt Lake City"
  current_certificate_task.request.subject.province = "Utah"
  current_certificate_task.request.subject.organization = "Venafi Inc"
  org_units = "engineering,marketing"
  array_org_units = org_units.split(',')
  current_certificate_task.request.subject.orgUnits = array_org_units
end

And(/^task named "(.*)" request has subject with "(.*)" value "(.*)"$/) do |task_name, key, value|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
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
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  cn = random_cn
  current_certificate_task.request.subject.commonName = cn
end

And(/^task named "(.*)" has installations$/) do |task_name|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.installations = Array.new
end

And(/^task named "(.*)" has installation format PEM with file name "(.*)", chain name "(.*)", key name "(.*)"(?: with)?( password)?(?:,| and)?( installation)?(?:,| and)?( validation)?(?: and uses)?( backup)?$/) do |task_name, cert_name, chain_name, key_name, password, installation, validation, backup|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  aux_installation = Installation.new
  aux_installation.format = "PEM"
  aux_installation.file = "{{- Env \"PWD\" }}" + $path_separator + $temp_path + $path_separator + cert_name
  aux_installation.chainFile = "{{- Env \"PWD\" }}" + $path_separator + $temp_path + $path_separator + chain_name
  aux_installation.keyFile = "{{- Env \"PWD\" }}" + $path_separator + $temp_path + $path_separator + + key_name
  if password
    aux_installation.keyPassword = "Passcode123!"
  if installation
    aux_installation.afterInstallAction = "echo SuccessInstall"
  end
  if validation
    aux_installation.installValidationAction = "echo SuccessValidation"
  end
  if backup
    aux_installation.backupFiles = true
  end
  current_certificate_task.installations.push(aux_installation)
end

And(/^task named "(.*)" has installation format JKS with cert name "(.*)", jksAlias "(.*)" and jksPassword "(.*)"(?: with)( installation)?(?: and|)( validation)?$/) do |task_name, cert_name, jks_alias, jks_password, installation, validation|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  aux_installation = Installation.new
  aux_installation.format = "JKS"
  aux_installation.file = "{{- Env \"PWD\" }}" + $path_separator + $temp_path + $path_separator + cert_name
  aux_installation.jksAlias = jks_alias
  aux_installation.jksPassword = jks_password
  if installation
    aux_installation.afterInstallAction = "echo SuccessInstall"
  end
  if validation
    aux_installation.installValidationAction = "echo SuccessValidation"
  end
  current_certificate_task.installations.push(aux_installation)
end

And(/^task named "(.*)" has installation format PKCS12 with cert name "(.*)" and password "(.*)"(?: with)( installation)?(?: and|)( validation)?$/) do |task_name, cert_name, p12_password, installation, validation|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  aux_installation = Installation.new
  aux_installation.format = "PKCS12"
  aux_installation.file = "{{- Env \"PWD\" }}" + $path_separator + $temp_path + $path_separator + cert_name
  aux_installation.p12Password = p12_password
  if installation
    aux_installation.afterInstallAction = "echo SuccessInstall"
  end
  if validation
    aux_installation.installValidationAction = "echo SuccessValidation"
  end
  current_certificate_task.installations.push(aux_installation)
end

And(/^task named "(.*)" has setenvvars "(.*)"$/) do |task_name, set_env_vars|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.setenvvars = set_env_vars.split(',')
end

And(/^task named "(.*)" has renewBefore with value "(.*)"$/) do |task_name, renew_before|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  current_certificate_task.renewBefore = renew_before
end

And(/^task named "(.*)" has request with nickname based on commonName$/) do |task_name|
  current_certificate_task = @playbook_data['certificateTasks'].find { |certificate_task| certificate_task.name == task_name }
  if current_certificate_task.request == Request.new
    fail(ArgumentError.new("Error while trying to set friendlyName based on commonName: no request defined"))
  end
  if current_certificate_task.request.subject == Subject.new
    fail(ArgumentError.new("Error while trying to set friendlyName based on commonName: no subject defined"))
  end
  if current_certificate_task.request.subject.commonName.nil? or current_certificate_task.request.subject.commonName == ""
    fail(ArgumentError.new("Error while trying to set friendlyName based on commonName: no commonName defined"))
  end
  current_certificate_task.request.nickname = "friendly.#{current_certificate_task.request.subject.commonName}"
end

And(/^I uninstall file named "(.*)"$/) do |file_name|
  file_path = Dir.pwd + $path_separator + $temp_path + $path_separator + file_name
  steps %{
    Then a file named "#{file_path}" does not exist
  }
end

When(/^playbook generated private key in "([^"]*)" and certificate in "([^"]*)" should have the same modulus(?: with password |)(.*)?$/) do |key_file, cert_file, password|
  cert_path = Dir.pwd + $path_separator + $temp_path + $path_separator + cert_file
  key_path = Dir.pwd + $path_separator + $temp_path + $path_separator + key_file

  if password != ""
    steps %{
      Then I run `openssl rsa -modulus -noout -passin pass:#{password} -in #{key_path}`
      And the exit status should be 0
    }
  else
    steps %{ Then I run `openssl rsa -modulus -noout -in #{key_path}` }
  end
  steps %{
    And I remember the output
    And I run `openssl x509 -modulus -noout -in #{cert_path}`
    Then the outputs should be the same
  }
end

When(/^playbook generated "([^"]*)" should be PKCS#12 archive with password "([^"]*)"$/) do |filename, password|
  cert_path = Dir.pwd + $path_separator + $temp_path + $path_separator + filename

  steps %{
    Then I try to run `openssl pkcs12 -in "#{cert_path}" -passin pass:#{password} -noout`
    And the exit status should be 0
  }
end

And(/^"(.*)" should( not)? be( encrypted)? RSA private key$/) do |filename, negated, encrypted|
  header = "-----BEGIN RSA PRIVATE KEY-----"
  file_path = Dir.pwd + $path_separator + $temp_path + $path_separator + filename

  lines = File.open(file_path).first(2).map(&:strip)

  if lines[0] == header then
    if lines[1].include?("ENCRYPTED")
      if negated
        fail(ArgumentError.new("Expected RSA key to not be encrypted but fail to found on second line: #{lines[1]}"))
      end
    else
      unless negated
        fail(ArgumentError.new("Expected RSA key to be encrypted but fail to found on second line: #{lines[1]}"))
      end
    end
  else
    fail(ArgumentError.new("Expected RSA key headers: #{header} but got in first line: #{lines[0]}"))
  end
end