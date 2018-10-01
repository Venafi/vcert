Feature: certificate revocation

  As a user
  I want to revoke certificates

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: revoking certificate using empty -id
    Then I revoke the certificate from TPP
    Then the output should contain "certificate DN or Thumbprint is required to revoke the certificate"

  Scenario: revoking certificate that does not exist
    When I revoke the certificate from TPP with -id xxx
    Then it should fail with "Certificate does not exist"

  Scenario: revoking certificate with incorrect reason
    When I revoke the certificate from TPP with -id someId -reason xxx
    Then it should fail with "xxx is not valid revocation reason"

  Scenario: revoking certificate using -id flag
    Given I enroll random certificate from TPP with -no-prompt
    And it should retrieve certificate
    When I revoke the certificate from TPP using the same Pickup ID
    Then the output should contain "Successfully created revocation request for"
    When I revoke the certificate from TPP using the same Pickup ID with -reason none
    Then the output should contain "Successfully created revocation request for"

  Scenario: revoking certificate using -id file:*.txt flag
    Given I enroll random certificate from TPP with -no-prompt -pickup-id-file p.txt
    And it should retrieve certificate
    Then I revoke the certificate from TPP with -id file:p.txt

  Scenario Outline: revoking certificates with different reasons
    Given I enroll random certificate from TPP with -no-prompt
    And I revoke the certificate from TPP using the same Pickup ID with -reason <reason>
    Then the output should contain "Successfully created revocation request for"
    Examples:
      | reason                  |
      | none                    |
      | key-compromise          |
      | ca-compromise           |
      | affiliation-changed     |
      | superseded              |
      | cessation-of-operation  |