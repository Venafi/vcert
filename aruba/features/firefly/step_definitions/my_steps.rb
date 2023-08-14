
When(/^I( interactively)? get credentials from "(.*)"(?: with)?(.+)?$/) do |interactively, identity_provider, flags|

  idp_token_url = ""
  idp_user = ""
  idp_password = ""
  idp_client_id = ""
  idp_client_secret = ""
  idp_scope = ""

  case identity_provider
  when "Okta"
    idp_token_url = "#{ENV['OKTA_AUTH_SERVER']}/v1/token"
    idp_user = ENV['OKTA_CREDS_USR']
    idp_password = ENV['OKTA_CREDS_PSW']
    if flags === " username and no password" || flags === " username and password"
      idp_client_id = ENV['OKTA_CLIENT_ID_PASS']
    else
      idp_client_id = ENV['OKTA_CLIENT_ID']
    end
    idp_client_secret = ENV['OKTA_CLIENT_SECRET']
    idp_scope = ENV['OKTA_SCOPE']
  else
    fail(ArgumentError.new("Unknown Identity Provider: #{identity_provider}"))
  end

  if flags === " username and no password"
    cmd = "vcert getcred -platform firefly -token-url '#{idp_token_url}' -client-id '#{idp_client_id}'" +
      " -username '#{idp_user}' -scope '#{idp_scope}'"
  elsif flags === " username and password"
    cmd = "vcert getcred -platform firefly -token-url '#{idp_token_url}' -client-id '#{idp_client_id}'" +
      " -username '#{idp_user}' -password '#{idp_password}' -scope '#{idp_scope}'"
  else
    # client id is our default
    cmd = "vcert getcred -platform firefly -token-url '#{idp_token_url}'" +
      " -client-id '#{idp_client_id}' -client-secret #{idp_client_secret} -scope '#{idp_scope}' #{flags}"
  end

  if interactively
    Kernel.puts cmd
    steps %{
      Then I run `#{cmd}` interactively
      And I type "#{idp_password}"
      Then the exit status should be 0
    }
  else
    steps %{
    Then I try to run `#{cmd}`
  }
  end
end