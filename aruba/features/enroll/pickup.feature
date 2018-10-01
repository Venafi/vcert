Feature: pickup is an action for retrieving certificates

  As a user
  I want to be able to retrieve certificate, chain and private key from remote endpoint

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: should write private key to -key-file if specified (makes sense only with -csr service)
    Given I enroll a certificate in test-mode with -no-prompt -cn vfidev.example.com -csr service -no-pickup -pickup-id-file p.txt
    Then I retrieve the certificate in test-mode with -pickup-id-file p.txt -key-password newPassw0rd!
    And it should retrieve certificate
    And it should output encrypted private key
