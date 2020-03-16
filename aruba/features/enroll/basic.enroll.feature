Feature: Enroll certificate

  As a user
  I want to enroll certificates

  Background:
    Given the default aruba exit timeout is 180 seconds

  Scenario: Simple enroll in test mode
    When I successfully run `vcert enroll -test-mode -test-mode-delay 0 -cn vfidev.example.com -no-prompt` for up to 10 seconds
    Then it should post certificate request
      And it should retrieve certificate

  Scenario: Enroll with interactive mode
    When I run `vcert enroll -test-mode -test-mode-delay 0 -cn vfidev.example.com` interactively
    And I type ""
    And I type ""
    Then it should post certificate request
    And it should retrieve certificate

  Scenario: Pass phrases don't match
    When I run `vcert enroll -test-mode -test-mode-delay 0 -cn vfidev.example.com` interactively
      And I type "newPassw0rd!"
      And I type "different password"
    Then it should fail with "Pass phrases don't match"

  Scenario: request a certificate with default arguments
    When I run `vcert enroll -test-mode -test-mode-delay 0 -cn vfidev.example.com -no-prompt -no-pickup`
    Then it should output private key
      And it should post certificate request

  Scenario: request a certificate with default arguments with -key-password
    When I run `vcert enroll -test-mode -test-mode-delay 0 -cn vfidev.example.com -no-prompt -no-pickup -key-password 1234`
    Then it should output encrypted private key
      And it should post certificate request

  Scenario: enroll a certificate with default arguments
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-pickup -no-prompt
    Then it should post certificate request
      And it should output private key

  Scenario: writing private key to file
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-pickup -no-prompt -key-file k.pem
    Then it should post certificate request
      And it should not output private key
      And the file named "k.pem" should exist

  Scenario: writing encrypted private key to file
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-pickup -no-prompt -key-file k.pem -key-password 1234
    Then it should post certificate request
      And "k.pem" should be RSA private key with password "1234"

  Scenario: writing encrypted private key to file with password readed from file
    Given a file named "password.txt" with "1234"
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-pickup -no-prompt -key-file k.pem -key-password file:password.txt
    Then it should post certificate request
      And "k.pem" should be RSA private key with password "1234"

  Scenario: request a certificate with 1024 key size
    Given I successfully run `vcert enroll -test-mode -test-mode-delay 0 -cn vfidev.example.com -no-prompt -cert-file c.pem -key-size 1024`
    Then "c.pem" should be a certificate with key size 1024 bits

  Scenario: request a certificate with default key size
    Given I enroll a certificate in test-mode with -cn vfidev.example.com -no-prompt -cert-file c.pem
    Then "c.pem" should be a certificate with key size 2048 bits

  Scenario: request a certificate with 3072 bit key size
    Given I enroll a certificate in test-mode with -cn vfidev.example.com -no-prompt -cert-file c.pem -key-size 3072
    Then "c.pem" should be a certificate with key size 3072 bits

  Scenario: when -chain-file option is not specified, then the chain is written to -cert-file
    Given I enroll a certificate in test-mode with -no-prompt -cn vfidev.example.com -cert-file c.pem
    Then the file "c.pem" should match /(-----BEGIN CERTIFICATE-----.+){2}/

  Scenario: when the chain is written to -chain-file
    Given I enroll a certificate in test-mode with -no-prompt -cn vfidev.example.com -cert-file c.pem -chain-file ch.pem
    Then the file "c.pem" should match /(-----BEGIN CERTIFICATE-----.+){1}/
    Then the file "ch.pem" should match /(-----BEGIN CERTIFICATE-----.+){1}/

  Scenario: enroll with wrong csr option should return error
    Given I enroll a certificate in test-mode with -cn vfidev.example.com -csr sservice -no-prompt
    Then the exit status should not be 0

  Scenario: enroll with custom field
    Given I enroll random certificate using TPP with -no-prompt -field "custom=12121" -field "Server Names=some server"
    Then the exit status should be 0

  Scenario: enroll with static instance and certificate and replace-instance
    Given I enroll certificate using TPP with  -cn devops-cert-with-instance.example.com -no-prompt -instance devops-instance:nginx_1234567890 -tls-address api-gw-myapp.example:8443  -app-info vcert:1.9.1 -replace-instance
    Then the exit status should be 0

  Scenario: enroll with random instance and app-info
    Given I enroll random certificate and_random_instance using TPP with -no-prompt -tls-address api-gw-myapp.example:8443  -app-info vcert:1.9.1
    Then the exit status should be 0

  Scenario: enroll with random instance and app-info and deprecated TPP
    Given I enroll random certificate and_random_instance using TPPdeprecated with -no-prompt -tls-address api-gw-myapp.example:8443  -app-info vcert:1.9.1
    Then the exit status should be 0

# todo: find a way to test with single instance and avoid ObjectAlreadyExists  error
#  Scenario: enroll with single instance and app-info
#    Given I enroll random certificate using TPP with -no-prompt -instance devops-instance -app-info vcert:1.9.1
#    Then the exit status should be 1

  Scenario: enroll with duplicated instance
    Given I enroll random certificate using TPP with -no-prompt -field "custom=12121" -field "Server Names=some server" -instance devops-instance:nginx_246 -instance devops-instance
    Then the exit status should be 1

  Scenario: enroll with duplicated tls-address
    Given I enroll random certificate using TPP with -no-prompt -field "custom=12121" -field "Server Names=some server" -tls-address api-gw-myapp.example:8443 -tls-address api-gw-myapp.example
    Then the exit status should be 1