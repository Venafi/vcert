Feature: renew action by -thumbprint

  As a user
  I want to renew certificates that were enrolled by the app

  Renew action requires a reference to some issued certificate:
  -id
  - for TPP -id is CertificateDN (like in `revoke` command)
  - for Condor -id points to some RequestID, which is used to find ManagedCertificateId then
  -thumbprint
  - for TPP & Condor -thumbprint is used to find CertificateDN / ManagedCertificateId respectively

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: TPP - renew by CertificateDN using -thumbprint
    Given I enroll random certificate using <endpoint> with -no-prompt -key-file k.pem -cert-file c.pem
    And it should write private key to the file "k.pem"
    And it should write certificate to the file "c.pem"
    And I decode certificate from file "c.pem"
    Then I renew the certificate in <endpoint> using the same Thumbprint with flags -no-prompt -cert-file c1.pem -key-file k1.pem
    And it should retrieve certificate
    And it should write private key to the file "k1.pem"
    And it should write certificate to the file "c1.pem"
    Then private key in "k1.pem" and certificate in "c1.pem" should have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same serial
    Examples:
      | endpoint  |
      | TPP       |
      | Cloud     |

  Scenario Outline: TPP - renew by CertificateDN using -thumbprint file:cert.pem
    Given I enroll random certificate using <endpoint> with -no-prompt -key-file k.pem -cert-file c.pem
    And it should write private key to the file "k.pem"
    And it should write certificate to the file "c.pem"
    Then I renew the certificate in <endpoint> with flags -thumbprint file:c.pem -no-prompt -cert-file c1.pem -key-file k1.pem
    And it should retrieve certificate
    And it should write private key to the file "k1.pem"
    And it should write certificate to the file "c1.pem"
    Then private key in "k1.pem" and certificate in "c1.pem" should have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same serial
    Examples:
      | endpoint  |
      | TPP       |
      | Cloud     |

