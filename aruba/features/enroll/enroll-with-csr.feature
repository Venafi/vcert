Feature: enrolling certificates with -csr option (VEN-40652)

  As a user
  I want to enroll either local-generated certificate requests or service-generated certificate requests
  or send existing CSR for signing

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: when it returns an error if both -cn and -csr file: options are used
    When I enroll a certificate in <endpoint> with -cn vdidev.example.com -csr file:csr.pem
    Then the exit status should not be 0
    And the output should contain "The '-cn' cannot be used in -csr file: provided mode"
    Examples:
    | endpoint  |
    | test-mode |
    | TPP       |
    | Cloud     |

  Scenario Outline: where it enrolls certificates with -csr file:csr.pem option
    Given I generate random CSR with -no-prompt -csr-file csr.pem -key-file k.pem
      And it should write CSR to the file named "csr.pem"
      And it should write private key to the file named "k.pem"
    And I enroll a certificate using <endpoint> with -csr file:csr.pem -no-pickup
      And it should post certificate request
    And I retrieve the certificate from <endpoint> using the same Pickup ID with -cert-file c.pem -chain-file ch.pem -timeout 190
    Then it should retrieve certificate
      And it should not output private key
      And CSR in "csr.pem" and private key in "k.pem" and certificate in "c.pem" should have the same modulus
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it enrolls certificates with -csr local -no-prompt
    Given I enroll random certificate using <endpoint> with -csr local -no-prompt
    And it should post certificate request
    Then it should retrieve certificate
    And it should output private key
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it enrolls certificates with -csr local -no-prompt -key-password ...
    Given I enroll random certificate using <endpoint> with -csr local -no-prompt -key-password newPassw0rd!
    And it should post certificate request
    Then it should retrieve certificate
    And it should output encrypted private key
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it returns an error on enrolling a certificate with -csr service and empty -key-password
    When I enroll random certificate using <endpoint> with -csr service -no-prompt
    Then the exit status should not be 0
    And the output should contain "-key-password cannot be empty in -csr service mode unless -no-pickup specified"
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it should however enroll a certificate with -csr service, empty -key-password and -no-pickup
    When I enroll random certificate using <endpoint> with -csr service -no-prompt -no-pickup
    Then it should post certificate request
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |

  Scenario Outline: where it should enroll a certificate with -csr service -no-prompt -key-password ...
    When I enroll random certificate using <endpoint> with -csr service -no-prompt -key-password newPassw0rd!
    Then it should post certificate request
      And it should retrieve certificate
      And it should output encrypted private key
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |

  Scenario Outline: where it should enroll a certificate with -csr service -no-prompt
    When I enroll random certificate using <endpoint> with -csr service -no-prompt -no-pickup
      Then it should post certificate request
    Then I retrieve the certificate using <endpoint> using the same Pickup ID with -timeout 59
      And it should retrieve certificate
      And it should not output private key
    Then I retrieve the certificate using <endpoint> using the same Pickup ID with -key-password newPassw0rd! -timeout 59
      And it should retrieve certificate
      And it should output encrypted private key
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |

