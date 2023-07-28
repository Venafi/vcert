require 'yaml'

When(/^I have playbook named "([^"]*)" with (\S+) connection details$/) do |fname, platform|

  config_block="""
  config:
  """

  connection_block="""
  connection:
  """

  if platform == "TPP"
    connection_block_tpp="""
    type: tpp
    credentials:
      clientId: vcert-sdk
      accessToken: #{ENV['TPP_ACCESS_TOKEN']}
    url: #{ENV['TPP_URL']}
    trustBundle: #{ENV['TPP_TRUST_BUNDLE']}
    """
    connection_block=connection_block+connection_block_tpp
  elsif platform == "VaaS"
    connection_block_vaas="""
    type: vaas
    credentials:
      apikey: #{ENV['CLOUD_APIKEY']}
    """
    connection_block=connection_block+connection_block_vaas
  end

  config_block="""
  config: #{connection_block}
  """

  steps %{
    Then a file named "#{fname}" with:
    """
    #{config_block}
    """
  }
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