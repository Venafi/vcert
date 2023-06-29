Feature: certificate retirement

  As a user
  I want to retire certificates

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: retire certificate using empty -id
    Then I retire the certificate from <endpoint>
    Then the output should contain "failed to create retire request: CertificateDN or Thumbprint required"
    Examples:
      | endpoint |
      | TPP      | 
      | Cloud    |

  Scenario: retire certificate that does not exist
    When I retire the certificate from <endpoint> with -id xxx
    Then it should fail with "Certificate does not exist"
    Examples:
      | endpoint |
      | TPP      | 
      | Cloud    |

  Scenario: retire certificate using -id flag
    Given I enroll random certificate from <endpoint> with -no-prompt
    And it should retrieve certificate
    When I retire the certificate from <endpoint> using the same Pickup ID
    Then the output should contain "Successfully created retire request for"
    Examples:
      | endpoint |
      | TPP      | 
      | Cloud    |

  Scenario: retire certificate using -id file:*.txt flag
    Given I enroll random certificate from <endpoint> with -no-prompt -pickup-id-file p.txt
    And it should retrieve certificate
    Then I retire the certificate from <endpoint> with -id file:p.txt
    Examples:
      | endpoint |
      | TPP      | 
      | Cloud    |

