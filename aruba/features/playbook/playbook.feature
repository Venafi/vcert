Feature: playbook

  As a user
  I want to retire certificates

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: run playbook
    Given I have playbook with TPP connection details
    And I have playbook with certificates block
    And I have playbook with task named "myCertificateInstallation"
#    And task named "myCertificateInstallation" has setenvars "thumbprint, serial"
#    And task named "myCertificateInstallation" has "renewBefore" with value "31d"
    And task named "myCertificateInstallation" has request
    # CA Distinguished Name
    And task named "myCertificateInstallation" has request with "cadn" value "VED/Policy/test/test.com"
    And task named "myCertificateInstallation" has request with "chainOption" value "root-first"
    And task named "myCertificateInstallation" has request with "csrOrigin" value "service"
#    And task named "myCertificateInstallation" has request with "customFields" value "custom="Foo",cfList="item1",cfListMulti="tier2|tier3|tier4""
    And task named "myCertificateInstallation" has request with "dnsNames" value "test.com,test2.com"
    And task named "myCertificateInstallation" has request with "emails" value "test@test.com,test2@test.com"
    And task named "myCertificateInstallation" has request with "fetchPrivateKey" value "true"
    And task named "myCertificateInstallation" has request with "friendlyName" value "test"
    And task named "myCertificateInstallation" has request with "ips" value "127.0.0.1"
    # m = Microsoft
    And task named "myCertificateInstallation" has request with "issuerHint" value "m"
    And task named "myCertificateInstallation" has request with "validDays" value "30"
    And task named "myCertificateInstallation" has request with "keyType" value "rsa"
    And task named "myCertificateInstallation" has request with "keyLength" value "4096"
    # "origin" is the full name for adding to meta information to certificate request
    And task named "myCertificateInstallation" has request with "origin" value "Venafi VCert CLI"
    And task named "myCertificateInstallation" has request with "upns" value "test"
    And task named "myCertificateInstallation" has request with "uris" value "uri.test.com"
    And task named "myCertificateInstallation" has request with "keyPassword" value "Passcode123!"
#    And task named "myCertificateInstallation" has request with default TPP zone
#    And task named "myCertificateInstallation" has request with Location instance "devops-instance", workload prefixed by "workload" and tlsaddress "wwww.example.com:443"
#    And task named "myCertificateInstallation" request has subject with "country" value "US"
#    And task named "myCertificateInstallation" request has subject with "locality" value "Salt Lake City"
#    And task named "myCertificateInstallation" request has subject with "province" value "Utah"
#    And task named "myCertificateInstallation" request has subject with "organization" value "Venafi Inc"
##    And task named "myCertificateInstallation" request has subject with "orgUnits" value "engineering,marketing"
#    And task named "myCertificateInstallation" request has installations





#    And I have playbook with task named with
#    And I append to "<config-file>" with:
#    """
#    setenvvars: ["thumbprint", "serial"]
#    renewBefore: 31d
#    """
#    And I append to "<config-file>" with:
#    """
#    request:
#      csrOrigin: service
#        keyPassword: "Passcode123!"
#        subject:
#          country: US
#          locality: Salt Lake City
#          province: Utah
#          organization: Venafi Inc
#          orgUnits:
#            - engineering
#            - marketing
#    """
#    And I append file named "<config-file>" with random common name
#    And I append file named "<config-file>" and "<platform>" connection details with zone
#    And I append file named "<config-file>" with installations block
#    And I append file named "<config-file>" with installation type PEM with cert name "cert.cer", chain name "chain.cer" and key name "key.pem" that uses installation script
#    And I append file named "<config-file>" with installation type JKS with jksAlias "venafi" and jksPassword "foobar123" that uses installation script
#    And I append file named "<config-file>" with installation type PKCS12 that uses installation script
    Then I created playbook named "<config-file>" with previous content

#    @TPP
#    Examples:
#      | config-file     | platform |
#      | playbook-tpp.yml| TPP      |
    Examples:
    | config-file     |
    | playbook-tpp.yml|

#    @VAAS
#    Examples:
#      | config-file       | platform |
#      | playbook-vaas.yml | VaaS     |