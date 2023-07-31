Feature: playbook

  As a user
  I want to issuie certificates using playbook and perform installation

  Background:
    And the default aruba exit timeout is 180 seconds

  @TPP
  Scenario Outline: run playbook
    Given I have playbook with TPP connection details
    And I have playbook with certificates block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has setenvvars "thumbprint,serial"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "chainOption" value "root-first"
    And task named "myCertificateInstallation" has request with "csrOrigin" value "service"
    And task named "myCertificateInstallation" has request with "customFields" value "custom="Foo",cfList="item1",cfListMulti="tier2|tier3|tier4""
    And task named "myCertificateInstallation" has request with "dnsNames" value "test.com,test2.com"
    And task named "myCertificateInstallation" has request with "emails" value "test@test.com,test2@test.com"
    And task named "myCertificateInstallation" has request with "fetchPrivateKey" value "true"
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
    And task named "myCertificateInstallation" has request with default TPP zone
    And task named "myCertificateInstallation" has request with Location instance "devops-instance", workload prefixed by "workload", tlsAddress "wwww.example.com:443" and replace "false"
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with "country" value "US"
    And task named "myCertificateInstallation" request has subject with "locality" value "Salt Lake City"
    And task named "myCertificateInstallation" request has subject with "province" value "Utah"
    And task named "myCertificateInstallation" request has subject with "organization" value "Venafi Inc"
    And task named "myCertificateInstallation" request has subject with "orgUnits" value "engineering,marketing"
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has request with friendlyName based on commonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation type PEM with cert name "cert.cer", chain name "chain.cer" and key name "key.pem" that uses installation script
    And task named "myCertificateInstallation" has installation type JKS with cert name "cert.jks", jksAlias "venafi" and jksPassword "foobar123" that uses installation script
    And task named "myCertificateInstallation" has installation type PKCS12 with cert name "cert.p12" that uses installation script
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file> --force-renew`
    Then the output should contain "Successfully executed installation validation actions"
    And the output should contain "playbook run finished"

    Examples:
    | config-file     |
    | playbook-tpp.yml|