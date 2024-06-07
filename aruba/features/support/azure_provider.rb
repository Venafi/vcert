# Define the necessary Azure credentials
CLIENT_ID = ENV['AZURE_CLIENT_ID']
CLIENT_SECRET = ENV['AZURE_CLIENT_SECRET']
TENANT_ID = ENV['AZURE_TENANT_ID']
KEYVAULT_NAME = ENV['AZURE_KEYVAULT_NAME']

def get_azure_access_token
  token_url = URI("https://login.microsoftonline.com/#{TENANT_ID}/oauth2/v2.0/token")
  token_request = Net::HTTP::Post.new(token_url)
  token_request.set_form_data({
    'grant_type' => 'client_credentials',
    'client_id' => CLIENT_ID,
    'client_secret' => CLIENT_SECRET,
    'scope' => 'https://vault.azure.net/.default'
  })

  begin
    token_response = Net::HTTP.start(token_url.hostname, token_url.port, use_ssl: true) do |http|
      http.request(token_request)
    end
    handle_http_response(token_response)

  rescue BadRequestError, UnauthorizedError, NotFoundError, ServerError => e
    puts "Custom Error: #{e.message}"
  rescue StandardError => e
    puts "An error occurred: #{e.message}"
  end

  token_data = JSON.parse(token_response.body)
  token_data['access_token']
end

def delete_azure_certificate(certificate_name)
  vault_url = URI("https://#{KEYVAULT_NAME}.vault.azure.net/certificates/#{certificate_name}?api-version=7.2")
  access_token = get_azure_access_token

  delete_request = Net::HTTP::Delete.new(vault_url)
  delete_request['Authorization'] = "Bearer #{access_token}"

  begin
    delete_response = Net::HTTP.start(vault_url.hostname, vault_url.port, use_ssl: true) do |http|
      http.request(delete_request)
    end
    handle_http_response(delete_response)
  rescue BadRequestError, UnauthorizedError, NotFoundError, ServerError => e
    puts "Custom Error: #{e.message}"
  rescue StandardError => e
    puts "An error occurred: #{e.message}"
  end
end