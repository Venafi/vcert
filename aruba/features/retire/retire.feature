Feature: certificate retirement

  As a user
  I want to retire certificates

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: retire certificate using empty -id
    Then I retire the certificate from <endpoint>
    Then the output should contain "Certificate DN or Thumbprint is required to revoke the certificate"
    Examples:
    | endpoint  |
    | TPP       |
    | Cloud     |

  Scenario: retire certificate that does not exist in TPP
    When I retire the certificate from TPP with -id xxx
    Then it should fail with "object with DN xxx doesn't exist"

  Scenario: retire certificate that does not exist in VaaS
    When I retire the certificate from Cloud with -id 'e9a98610-22aa-11ee-81be-3d121e6033c4'
    Then it should fail with "Invalid thumbprint or certificate ID. No certificates were retired"

  Scenario: retire certificate using -id flag
    Given I enroll random certificate from <endpoint> with -no-prompt
    And it should retrieve certificate
    When I retire the certificate from <endpoint> using the same Pickup ID
    Then the output should contain "Successfully retired certificate"
    Examples:
    | endpoint  |
    | TPP       |
    | Cloud     |

  Scenario: retire certificate using -id file:*.txt flag
    Given I enroll random certificate from <endpoint> with -no-prompt -pickup-id-file p.txt
    And it should retrieve certificate
    Then I retire the certificate from <endpoint> with -id file:p.txt
    Examples:
    | endpoint  |
    | TPP       |
    | Cloud     |
