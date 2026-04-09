Feature: provision to cloud keystore

  As a user
  I want provision certificates to cloud keystore from Venafi Control Plane or NGTS

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: Enroll certificate and execute provisioning for cloud keystore
    Given I enroll a random certificate with defined platform <platform> with -csr service -no-prompt
    And I remember the output
    And I use previous Pickup ID to provision from <platform> a certificate to cloudkeystore "<cloudkeystore>" setting keystore and provider names
    And I remember the output
      And the output should not contain "Warning: --platform not set. Attempting to best-guess platform from connection flags"
    And I grab cloud ID from output
    Then I clean up previous installed certificate from cloudkeystore

    @VAAS
    Examples:
      | platform | cloudkeystore |
      | VCP      | GOOGLE        |
      | VCP      | AWS           |
      | VCP      | AZURE         |

    @NGTS
    Examples:
      | platform | cloudkeystore |
      | NGTS     | GOOGLE        |
      | NGTS     | AWS           |
      | NGTS     | AZURE         |

  Scenario Outline: Enroll certificate and execute provisioning for cloud keystore without Platform flags
    Given I enroll a random certificate with defined platform <platform> with -csr service -no-prompt
    And I remember the output
    And I use previous Pickup ID to provision without set Platform flag from <platform> a certificate to cloudkeystore "<cloudkeystore>" setting keystore and provider names
    And I remember the output
      And the output should contain "Warning: --platform not set. Attempting to best-guess platform from connection flags"
    And I grab cloud ID from output
    Then I clean up previous installed certificate from cloudkeystore

    @VAAS
    Examples:
      | platform | cloudkeystore |
      | VCP      | GOOGLE        |
      | VCP      | AWS           |
      | VCP      | AZURE         |

    @NGTS
    Examples:
      | platform | cloudkeystore |
      | NGTS     | GOOGLE        |
      | NGTS     | AWS           |
      | NGTS     | AZURE         |

  Scenario Outline: Enroll certificate and execute provisioning for cloud keystore and get output in JSON
    Given I enroll a random certificate with defined platform <platform> with -csr service -no-prompt
    And I remember the output
    And I use previous Pickup ID to provision from <platform> a certificate to cloudkeystore "<cloudkeystore>" setting keystore and provider names with -format json
    And I remember the output
    And I grab cloud ID from JSON output
    Then I clean up previous installed certificate from cloudkeystore

    @VAAS
    Examples:
      | platform | cloudkeystore |
      | VCP      | GOOGLE        |
      | VCP      | AWS           |
      | VCP      | AZURE         |

    @NGTS
    Examples:
      | platform | cloudkeystore |
      | NGTS     | GOOGLE        |
      | NGTS     | AWS           |
      | NGTS     | AZURE         |

  Scenario Outline: Enroll certificate, execute provisioning and then provisioning again for replace
    Given I enroll a random certificate with defined platform <platform> with -csr service -no-prompt
    And I remember the output
    And I use previous Pickup ID to provision from <platform> a certificate to cloudkeystore "<cloudkeystore>" setting keystore and provider names
    And I remember the output
      And the output should contain "cloudId:"
      And the output should contain "machineIdentityActionType: New"
    And I grab cloud ID from output
    Then I use previous Pickup ID and cloud ID to provision again for <platform>
      And I remember the output
      And the output should contain the previous cloud ID
      And the output should contain "machineIdentityActionType: ReProvision"
    Then I clean up previous installed certificate from cloudkeystore

    @VAAS
    Examples:
      | platform | cloudkeystore |
      | VCP      | AWS           |
      | VCP      | GOOGLE        |
      | VCP      | AZURE         |

    @NGTS
    Examples:
      | platform | cloudkeystore |
      | NGTS     | AWS           |
      | NGTS     | GOOGLE        |
      | NGTS     | AZURE         |


  Scenario Outline: Enroll certificate and execute provisioning for cloud keystore on GCM using certificate's scopes
      Given I enroll a random certificate with defined platform <platform> with -csr service -no-prompt
      And I remember the output
      And I use previous Pickup ID to provision from <platform> a certificate to cloudkeystore "<cloudkeystore>" setting keystore and provider names with -gcm-cert-scope DEFAULT
      And I remember the output
        And the output should not contain "Warning: --platform not set. Attempting to best-guess platform from connection flags"
      And I grab cloud ID from output
      Then I clean up previous installed certificate from cloudkeystore

      @VAAS
      Examples:
        | platform | cloudkeystore |
        | VCP      | GOOGLE        |

      @NGTS
      Examples:
        | platform | cloudkeystore |
        | NGTS     | GOOGLE        |
