Feature: Generating simple certificate request

  As a user I want to generate certificate requests (CSR)

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: where CSR is generated interactively with empty key-password
    When I run `vcert gencsr -cn vfidev.example.com` interactively
    And I type ""
    And I type ""
    Then the exit status should be 0
    And it should output private key
    And it should output CSR

  Scenario: where CSR is generated interactively with non-empty key-password
    When I run `vcert gencsr -cn vfidev.example.com` interactively
    And I type "newPassw0rd!"
    And I type "newPassw0rd!"
    Then the exit status should be 0
    And it should output encrypted private key
    And it should output CSR

  Scenario: where CSR is generated with -no-prompt
    When I run `vcert gencsr -cn vfidev.example.com -no-prompt`
    Then the exit status should be 0
    And it should output private key
    And it should output CSR

  Scenario: where CSR is generated and the private key is encrypted
    When I run `vcert gencsr -cn vfidev.example.com -key-password newPassw0rd!`
    Then the exit status should be 0
    And it should output encrypted private key
    And it should output CSR

  Scenario: where although -csr-file option is ignored - VEN-41637
    When I run `vcert gencsr -cn vfidev.example.com -no-prompt -csr-file csr.pem`
    Then the exit status should be 0
    And it should output private key
    And it should output CSR
    But it should not write CSR to the file named "csr.pem"

  Scenario: where -csr-file and -key-file options are both specified
    When I run `vcert gencsr -cn vfidev.example.com -no-prompt -csr-file csr.pem -key-file k.pem`
    Then the exit status should be 0
      And it should write CSR to the file named "csr.pem"
      And it should write private key to the file named "k.pem"
        And it should not output private key
        And it should not output CSR
        And the output should be 0 bytes long
