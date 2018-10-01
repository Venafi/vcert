Feature: renew action with -csr file:csr.pem option

  As a user
  I want to renew certificates that were enrolled by the app
  Using `-csr file:*` option meaning that provided CSR will be sent for signing to substitute old certificate

  New certificate will have the same modulus as an old one.

  It only works if service side allows key reuse. Error is returned otherwise

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: where the same CSR is sent for renew
    Given I generate random CSR with -key-file k.pem -csr-file csr.pem -no-prompt
      And it should write private key to the file "k.pem"
      And it should write CSR to the file named "csr.pem"
    Then I enroll certificate using <endpoint> with -csr file:csr.pem -cert-file c.pem
      And it should retrieve certificate
      And it should write certificate to the file "c.pem"
    Then I renew the certificate in <endpoint> using the same Pickup ID with flags -csr file:csr.pem -cert-file c1.pem
      And it should retrieve certificate
      And it should write certificate to the file "c1.pem"
      But it should not output private key
    Then certificate in "c.pem" and certificate in "c1.pem" should have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same serial
    Examples:
      | endpoint  |
      | TPP       |
      | Cloud     |

  Scenario Outline: where different CSR is sent for renew
    Given I enroll random certificate using <endpoint> with -no-prompt -key-file k.pem -cert-file c.pem
    And it should retrieve certificate

    Given I generate random CSR with -key-file k1.pem -csr-file csr1.pem -no-prompt
    And it should write private key to the file "k1.pem"
    And it should write CSR to the file named "csr1.pem"

    Then I renew the certificate in <endpoint> using the same Pickup ID with flags -csr file:csr1.pem -cert-file c1.pem
    And it should retrieve certificate
    And it should write certificate to the file "c1.pem"
    But it should not output private key

    Then certificate in "c.pem" and certificate in "c1.pem" should not have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same serial
    Examples:
      | endpoint  |
      | TPP       |
      | Cloud     |
