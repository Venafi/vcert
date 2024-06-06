require 'aws-sdk-acm'

# Initialize the Certificate Manager Client
def create_aws_certificate_manager_client
  Aws::ACM::Client.new(
    region: ENV['AWS_REGION'],
    access_key_id: ENV['AWS_ACCESS_KEY_ID'],
    secret_access_key: ENV['AWS_SECRET_ACCESS_KEY']
  )
end

# Delete a certificate
def delete_acm_certificate(client, certificate_arn)
  begin
    client.delete_certificate({ certificate_arn: certificate_arn })
    puts "Certificate with ARN #{certificate_arn} deleted successfully."
  rescue Aws::ACM::Errors::ServiceError => e
    puts "Error deleting certificate: #{e.message}"
  end
end
