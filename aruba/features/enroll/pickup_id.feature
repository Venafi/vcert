Feature: -pickup-id feature

  VEN-41305

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: The PickupID is only present in STDOUT when the pickup-id-file parameter is not specified
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-prompt
    Then it should output Pickup ID

  Scenario: The PickupID is only present in STDOUT when the pickup-id-file parameter is not specified
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-prompt -file all.pem
    Then it should output Pickup ID

  Scenario: The PickupID is only present in STDOUT when the pickup-id-file parameter is not specified
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-prompt -pickup-id-file p.txt
    Then it should not output Pickup ID
    And it should write Pickup ID to a file named "p.txt"

  Scenario: If the pickup-id-file parameter is not specified and the -format parameter is "json", the "PickupID" is included in the JSON body written to STDOUT
    Given I enroll a certificate in test-mode with -no-prompt -cn vfidev.example.com -format json
    And the JSON response should have "Certificate"
    And the JSON response should have "PrivateKey"
    And the JSON response should have "Chain"
    And the JSON response should have "PickupId"

  Scenario: If the pickup-id-file parameter is not specified, the -format parameter is "json" and the -file parameter is specified, the "PickupID" is the only data present in the JSON body written to STDOUT
    Given I enroll a certificate in test-mode with -no-prompt -cn vfidev.example.com -format json -file all.json
    And the JSON response should not have "Certificate"
    And the JSON response should not have "PrivateKey"
    And the JSON response should not have "Chain"
    And the JSON response should have "PickupId"

  Scenario: requesting and retrieving certificate by Pickup ID
    When I enroll a certificate in test-mode with -cn vfidev.example.com -no-pickup -no-prompt
    Then it should post certificate request
    And it should output Pickup ID
    Then I retrieve the certificate from test-mode using the same Pickup ID
    And it should retrieve certificate

  Scenario: request a certificate and write Pickup ID to a file
    Given I enroll a certificate in test-mode with -cn vfidev.example.com -no-prompt -no-pickup -pickup-id-file p.txt
    Then it should post certificate request
    Then I retrieve the certificate from test-mode with -pickup-id-file p.txt
    And it should retrieve certificate

  Scenario: An error is returned if both the pickup-id and pickup-id-file parameters are specified for the pickup command
    Given I enroll a certificate in test-mode with -cn vfidev.example.com -no-prompt -no-pickup -pickup-id-file p.txt
    And I retrieve the certificate from test-mode with -pickup-id-file p.txt -pickup-id xxx
    Then the exit status should not be 0
    And the output should contain "Both -pickup-id and -pickup-id-file options cannot be specified at the same time"
