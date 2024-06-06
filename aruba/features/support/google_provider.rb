require 'google/cloud/certificate_manager/v1'

# Set the environment variable for Google Cloud credentials
ENV['GOOGLE_APPLICATION_CREDENTIALS'] = ENV['GCP_AUTH_PATH']

# Initialize the Certificate Manager Client
def create_google_certificate_manager_client
  Google::Cloud::CertificateManager::V1::CertificateManager::Client.new
end

# Delete a certificate
def delete_gcm_certificate(client, certificate_name)
  request = Google::Cloud::CertificateManager::V1::DeleteCertificateRequest.new(
    name: certificate_name
  )

  operation = client.delete_certificate(request)
  operation.wait_until_done!

  if operation.error?
    puts "Error deleting certificate: #{operation.error.message}"
  else
    puts "Certificate deleted successfully."
  end
end
