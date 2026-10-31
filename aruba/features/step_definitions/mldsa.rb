require 'openssl'

# ML-DSA public key algorithm OIDs (FIPS 204)
MLDSA_OIDS = {
  "2.16.840.1.101.3.4.3.17" => 44,
  "2.16.840.1.101.3.4.3.18" => 65,
  "2.16.840.1.101.3.4.3.19" => 87,
}

# Certificates and CSRs are read as plain ASN.1, which works for any algorithm whatever the OpenSSL version of the test
# image. Returns the SubjectPublicKeyInfo of the first certificate or CSR in the file.
def subject_public_key_info(filename)
  pem = File.read(expand_path(filename))
  m = pem.match(/-----BEGIN (?:NEW )?(?:CERTIFICATE|CERTIFICATE REQUEST)-----(.+?)-----END/m)
  raise "no certificate or CSR found in #{filename}" unless m

  # Certificate: [tbsCertificate, signatureAlgorithm, signature]; CSR: [certificationRequestInfo, ...]. In both, the
  # SubjectPublicKeyInfo is the SEQUENCE { SEQUENCE { OID, ... }, BIT STRING } inside the first element.
  info = OpenSSL::ASN1.decode(m[1].unpack1('m')).value[0]
  spki = info.value.find do |e|
    e.is_a?(OpenSSL::ASN1::Sequence) &&
      e.value[0].is_a?(OpenSSL::ASN1::Sequence) &&
      e.value[0].value[0].is_a?(OpenSSL::ASN1::ObjectId) &&
      e.value[1].is_a?(OpenSSL::ASN1::BitString)
  end
  raise "no public key found in #{filename}" unless spki
  spki
end

Then(/^"([^"]*)" should be a (?:certificate|CSR) with an ML-DSA-(44|65|87) public key$/) do |filename, strength|
  oid = subject_public_key_info(filename).value[0].value[0].oid
  expect(MLDSA_OIDS[oid]).to eq(strength.to_i), "expected an ML-DSA-#{strength} public key in #{filename}, got OID #{oid}"
end

Then(/^CSR in "([^"]*)" and certificate in "([^"]*)" should have the same public key$/) do |csr_file, cert_file|
  expect(subject_public_key_info(cert_file).to_der).to eq(subject_public_key_info(csr_file).to_der)
end

# Needs OpenSSL 3.5 or later in the test image to read ML-DSA private keys
Then(/^private key in "([^"]*)"( encrypted with dummy password)? and certificate in "([^"]*)" should have the same public key$/) do |key_file, encrypted, cert_file|
  passin = encrypted ? " -passin pass:#{DUMMY_PASSWORD}" : ""
  steps %{
    When I run `openssl pkey -pubout -in #{key_file}#{passin}`
    And the exit status should be 0
    And I remember the output
    And I run `openssl x509 -pubkey -noout -in #{cert_file}`
    Then the outputs should be the same
  }
end

Then(/^"([^"]*)" should be an encrypted PKCS#8 private key$/) do |filename|
  steps %{
    Then the file named "#{filename}" should contain "-----BEGIN ENCRYPTED PRIVATE KEY-----"
  }
end
