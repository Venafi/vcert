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
