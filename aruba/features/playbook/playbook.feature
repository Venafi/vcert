Feature: playbook

  As a user
  I want to retire certificates

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: run playbook
    Given I have file named "<config-file>" with <platform> connection details
    And I append file named "<config-file>" with certificates block
    And I append file named "<config-file>" with task named "myCertificateInstallation"
    And I append to "<config-file>" with:
    """
    setenvvars: ["thumbprint", "serial"]
    renewBefore: 31d
    """
    And I append to "<config-file>" with:
    """
    request:
      csrOrigin: service
        keyPassword: "Passcode123!"
        subject:
          country: US
          locality: Salt Lake City
          province: Utah
          organization: Venafi Inc
          orgUnits:
            - engineering
            - marketing
    """
    And I append file named "<config-file>" with random common name
    And I append file named "<config-file>" and "<platform>" connection details with zone
    And I append file named "<config-file>" with installations block
    And I append file named "<config-file>" with installation type PEM with cert name "cert.cer", chain name "chain.cer" and key name "key.pem" that uses installation script
    And I append file named "<config-file>" with installation type JKS with jksAlias "venafi" and jksPassword "foobar123" that uses installation script
    And I append file named "<config-file>" with installation type PKCS12 that uses installation script
    Then a file named "<config-file>" should exist

    @TPP
    Examples:
      | config-file     | platform |
      | playbook-tpp.yml| TPP      |

    @VAAS
    Examples:
      | config-file       | platform |
      | playbook-vaas.yml | VaaS     |