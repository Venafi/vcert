


Then(/^I get JSON response$/) do

  JSON.parse(last_json)

  begin
    certificate_pem_block = unescape_text(normalize_json(last_json, "Certificate")).tr('"', '')
    tmp_file = random_filename
    steps %{
      Given the file named "#{tmp_file}" with:
      """
      #{certificate_pem_block}
      """
      And I decode certificate from file "#{tmp_file}"
    }
  rescue
    # there was no "Certificate" path
  end

end

When(/^I decode CSR from file "([^"]*)"$/) do |filename|
  steps %{
    Then I run `openssl req -text -noout -in "#{filename}"`
    And the exit status should be 0
  }
  @csr_text = last_command_started.output.to_s
end

When(/^I decode certificate from file "([^"]+)"$/) do |filename|
  steps %{
    Then I try to run `openssl x509 -text -fingerprint -noout -in "#{filename}"`
    And the exit status should be 0
  }
  @certificate_text = last_command_started.output.to_s

  m = last_command_started.output.match /^SHA1 Fingerprint=(\S+)$/
  if m
    @certificate_fingerprint = m[1]
  end
end

When(/^that (CSR|certificate)?( Subject)? should( not)? contain "([^"]*)"$/) do |block, subject, negated, expected|
  text = case block
         when "CSR" then @csr_text
         when "certificate" then @certificate_text
         else ""
         end
  if subject
    if negated
      expect(text).not_to match(/Subject.+#{expected}/)
    else
      expect(text).to match(/Subject.+#{expected}/)
    end
  else
    if negated
      expect(text).not_to send(:an_output_string_including, expected)
    else
      expect(text).to send(:an_output_string_including, expected)
    end
  end
end

When(/^CSR in "([^"]*)" file and private key in "([^"]*)" file should( not)? have the same modulus$/) do |csr_file, key_file, negated|
  steps %{
    When I run `openssl req -modulus -noout -in #{csr_file}`
    And I remember the output
    And I run `openssl rsa -modulus -passin pass:newPassw0rd! -noout -in #{key_file}`
    Then the outputs should#{negated} be the same
  }
end

When(/^CSR in "([^"]*)" and private key in "([^"]*)" and certificate in "([^"]*)" should have the same modulus$/) do |csr_file, key_file, cert_file|
  steps %{
    Then I run `openssl req -modulus -noout -in #{csr_file}`
    And I remember the output
    Then I run `openssl rsa -modulus -passin pass:newPassw0rd! -noout -in #{key_file}`
    And the outputs should be the same
    And I remember the output
    And I run `openssl x509 -modulus -noout -in #{cert_file}`
    Then the outputs should be the same
  }
end

When(/^private key in "([^"]*)" and certificate in "([^"]*)" should have the same modulus$/) do |key_file, cert_file|
  steps %{
    Then I run `openssl rsa -modulus -noout -passin pass:newPassw0rd! -in #{key_file}`
    And I remember the output
    And I run `openssl x509 -modulus -noout -in #{cert_file}`
    Then the outputs should be the same
  }
end

When(/^certificate in "([^"]*)" and certificate in "([^"]*)" should( not)? have the same (modulus|serial)$/) do |cert1_file, cert2_file, negated, field|
  steps %{
    When I run `openssl x509 -#{field} -noout -in #{cert1_file}`
    And I remember the output
    And I run `openssl x509 -#{field} -noout -in #{cert2_file}`
    Then the outputs should#{negated} be the same
  }
end

When(/^"([^"]*)" should be a certificate with key size (\d+) bits$/) do |cert_file, bit_len|
  steps %{
    Then I decode certificate from file "#{cert_file}"
    And the output should contain "Public-Key: (#{bit_len} bit)"
  }
end

When(/^"([^"]*)" should be PKCS#12 archive with password "([^"]*)"$/) do |filename, password|
  steps %{
    Then I try to run `openssl pkcs12 -in "#{filename}" -passin pass:#{password} -noout`
    And the exit status should be 0
    And the output should be 0 bytes long
  }
  # -nokeys           Don't output private keys
  # -nocerts          Don't output certificates
  # -clcerts          Only output client certificates
  # -cacerts          Only output CA certificates
  # -noout            Don't output anything, just verify
  # -nodes            Don't encrypt private keys
end
