Feature: PKCS#12 format output

  As user, I need VCert to output my certificate, private key, and chain certificates in the PKCS#12 format
  required by my application so that I don't have to use OpenSSL to combine the individual PEM files generated
  by VCert into a PKCS#12 keystore.

  - User requests PKCS#12 by specifying "pkcs12" after the -format switch

  - User must use the -file switch to specify the name of the keystore file when they specify -format pkcs12
    (i.e. neither the -cert-file, -key-file, nor -chain-file switches may appear on the command line,
    and console output as a base64 encoded blob will not be supported).

  - User specifies the password for the PKCS#12 file using the -key-password switch

  - User can request a PKCS#12 file with no password by including the -no-prompt switch

  - PKCS#12 format is not allowed for the enroll or renew actions when -csr is "file"

  - PKCS#12 format is not allowed for the enroll or renew action when -csr is "local" (or not specified)
    and the -no-pickup switch is used

  - PKCS#12 format is only allowed for the pickup action when the private key is stored in the Venafi Platform

  
  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: where it outputs error if PKCS#12 format is specified, but STDOUT output is used (default output)
    When I enroll random certificate in test-mode with -no-prompt -format pkcs12
      Then it should fail with "PKCS#12 format can only be used if all objects are written to one file (see -file option)"
    When I retrieve the certificate in test-mode with -pickup-id xxx -no-prompt -format pkcs12
      Then it should fail with "PKCS#12 format can only be used if all objects are written to one file (see -file option)"
    When I renew the certificate in TPP with flags -id xxx -no-prompt -format pkcs12
      Then it should fail with "PKCS#12 format can only be used if all objects are written to one file (see -file option)"

  Scenario: where all objects are written to one PKCS#12 archive
    When I enroll random certificate in test-mode with -no-prompt -format pkcs12 -file all.p12
    Then the exit status should be 0
    And "all.p12" should be PKCS#12 archive with password ""

  Scenario: where all objects are written to one PKCS#12 archive with ecdsa key
    When I enroll random certificate in test-mode with -no-prompt -format pkcs12 -file all.p12 -key-type ecdsa
    Then the exit status should be 0
    And "all.p12" should be PKCS#12 archive with password ""

  Scenario Outline: where all objects are written to one PKCS#12 archive with key password
    When I enroll random certificate in <endpoint> with -format pkcs12 -file all.p12 -key-password newPassw0rd!
    Then the exit status should be 0
    And "all.p12" should be PKCS#12 archive with password "newPassw0rd!"
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it outputs error when trying to pickup local-generated certificate and output it in PKCS#12 format
    When I enroll random certificate using <endpoint> with -no-prompt -no-pickup
    And I retrieve the certificate using <endpoint> using the same Pickup ID with -timeout 99 -no-prompt -file all.p12 -format pkcs12
    And it should fail with "failed to encode pkcs12: at least certificate and private key are required"
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it outputs error when trying to enroll certificate in -csr file: mode and output it in PKCS#12 format
    Given I generate random CSR with -no-prompt -csr-file csr.pem -key-file k.pem
    When I enroll certificate using <endpoint> with -no-prompt -csr file:csr.pem -file all.p12 -format pkcs12
    And it should fail with "PKCS#12 format is not allowed for the enroll or renew actions when -csr is \"file\""
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it outputs error when trying to enroll certificate in -csr local (by default), -no-pickup and output it in PKCS#12 format
    When I enroll random certificate using <endpoint> with -no-prompt -file all.p12 -format pkcs12 -no-pickup
    And it should fail with "PKCS#12 format is not allowed for the enroll or renew actions when -csr is "local" and -no-pickup is specified"
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it outputs error when trying to enroll certificate in -csr local (specified), -no-pickup and output it in PKCS#12 format
    When I enroll random certificate using <endpoint> with -no-prompt -file all.p12 -format pkcs12 -no-pickup -csr local
    And it should fail with "PKCS#12 format is not allowed for the enroll or renew actions when -csr is "local" and -no-pickup is specified"
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      | Cloud     |

  Scenario Outline: where it pickups up service-generated certificate and outputs it in PKCS#12 format
    When I enroll random certificate using <endpoint> with -no-prompt -no-pickup -csr service
    And I retrieve the certificate using <endpoint> using the same Pickup ID with -timeout 99 -key-password newPassw0rd! -file all.p12 -format pkcs12
    And "all.p12" should be PKCS#12 archive with password "newPassw0rd!"
    Examples:
      | endpoint  |
      | test-mode |
      | TPP       |
      # | Cloud     | # -csr service is not supported by Cloud