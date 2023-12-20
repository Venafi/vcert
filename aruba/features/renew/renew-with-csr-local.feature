Feature: renew action with -csr local (default) option

  As a user
  I want to renew certificates that were enrolled by the app
  Using `-csr local` option (which is default) meaning that new private key and CSR are generated locally
  and then sent for signing to substitute old certificate

  New certificate will have different modulus in this case and the command outputs newly generated private key

  for TPP & Condor:
    - 1st it downloads current certificate using -id or -thumbprint
    - it constructs similar certificate request based on certificate downloaded
    - it overrides certificate request based on allowed command line options (like -key-size, -san-dns etc.)
    - then it acts like enroll: generate new key & CSR locally, pushes CSR to service side, gets new cert back, outputs key, cert, chain, pickupId

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: renew certificate using -id without specifying -csr option
    Given I enroll random certificate using <endpoint> with -no-prompt -key-file k.pem -cert-file c.pem
    And it should write private key to the file "k.pem"
    And it should write certificate to the file "c.pem"
    And it should output Pickup ID
    And I decode certificate from file "c.pem"
    Then I renew the certificate in <endpoint> using the same Pickup ID with flags -no-prompt -cert-file c1.pem -key-file k1.pem
    And it should retrieve certificate
    And it should write private key to the file "k1.pem"
    And it should write certificate to the file "c1.pem"
    Then private key in "k1.pem" and certificate in "c1.pem" should have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same serial

    @TPP
    Examples:
      | endpoint  |
      | TPP       |

    @VAAS
    Examples:
      | endpoint  |
      | Cloud     |

  Scenario Outline: renew certificate using -id using `-csr local`
    Given I enroll random certificate using <endpoint> with -no-prompt -key-file k.pem -cert-file c.pem -csr local
      And it should write private key to the file "k.pem"
      And it should write certificate to the file "c.pem"
      And it should output Pickup ID
    And I decode certificate from file "c.pem"
    Then I renew the certificate in <endpoint> using the same Pickup ID with flags -no-prompt -cert-file c1.pem -key-file k1.pem
      And it should retrieve certificate
      And it should write private key to the file "k1.pem"
      And it should write certificate to the file "c1.pem"
    Then private key in "k1.pem" and certificate in "c1.pem" should have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same modulus
    And certificate in "c.pem" and certificate in "c1.pem" should not have the same serial

    @TPP
    Examples:
      | endpoint  |
      | TPP       |

    @VAAS
    Examples:
      | endpoint  |
      | Cloud     |

  Scenario Outline: renew certificate using -id using `-csr local` with PKCS12 flag
    Given I enroll random certificate using <endpoint> with -key-password Passcode123! -key-file k.pem -cert-file c.pem -csr local
      And it should write private key to the file "k.pem"
      And it should write certificate to the file "c.pem"
      And it should output Pickup ID
    And I decode certificate from file "c.pem"
    Then I renew the certificate in <endpoint> using the same Pickup ID with flags -key-password Passcode123! -file all.p12 -format pkcs12
      And it should retrieve certificate
      And "all.p12" should be PKCS#12 archive with password "Passcode123!"

    @TPP
    Examples:
      | endpoint  |
      | TPP       |

    @VAAS
    Examples:
      | endpoint  |
      | Cloud     |

  Scenario Outline: renew certificate using -id using `-csr local` with PKCS12 legacy flag
    Given I enroll random certificate using <endpoint> with -key-password Passcode123! -key-file k.pem -cert-file c.pem -csr local
      And it should write private key to the file "k.pem"
      And it should write certificate to the file "c.pem"
      And it should output Pickup ID
    And I decode certificate from file "c.pem"
    Then I renew the certificate in <endpoint> using the same Pickup ID with flags -key-password Passcode123! -file all.p12 -format legacy-pkcs12
      And it should retrieve certificate
      And "all.p12" should be PKCS#12 archive in legacy mode with password "Passcode123!"

    @TPP
    Examples:
      | endpoint  |
      | TPP       |

    @VAAS
    Examples:
      | endpoint  |
      | Cloud     |

    Scenario: where renewed certificate may have new  -key-size, -san-dns
      Given I implement that later
