Feature: playbook

  As a user
  I want to issue certificates using playbook and perform installation

  Background:
    And the default aruba exit timeout is 180 seconds

  @TPP
  Scenario Outline: Run playbook for TPP with extended configuration with PEM, PKCS12 and JKS installations
    Given I have playbook with TPP connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has setenvvars "thumbprint,serial"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "chain" value "root-first"
    And task named "myCertificateInstallation" has request with "csr" value "service"
    And task named "myCertificateInstallation" has request with "fields" value "custom="Foo",cfList="item1",cfListMulti="tier2|tier3|tier4""
    And task named "myCertificateInstallation" has request with "sanDns" value "test.com,test2.com"
    And task named "myCertificateInstallation" has request with "sanEmail" value "test@test.com,test2@test.com"
    And task named "myCertificateInstallation" has request with "fetchPrivateKey" value "true"
    And task named "myCertificateInstallation" has request with "sanIP" value "127.0.0.1,192.168.1.2"
    # m = Microsoft
    And task named "myCertificateInstallation" has request with "issuerHint" value "m"
    And task named "myCertificateInstallation" has request with "validDays" value "30"
    And task named "myCertificateInstallation" has request with "keyType" value "rsa"
    And task named "myCertificateInstallation" has request with "keySize" value "4096"
    # "origin" is the full name for adding to meta information to certificate request
    And task named "myCertificateInstallation" has request with "appInfo" value "Venafi VCert Playbook"
    And task named "myCertificateInstallation" has request with "sanUpn" value "test,test2"
    And task named "myCertificateInstallation" has request with "sanUri" value "uri.test.com,foo.venafi.com"
    And task named "myCertificateInstallation" has request with default "TPP" zone
    And task named "myCertificateInstallation" has request with Location instance "devops-instance", workload prefixed by "workload", tlsAddress "wwww.example.com:443" and replace "false"
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with "country" value "US"
    And task named "myCertificateInstallation" request has subject with "locality" value "Salt Lake City"
    And task named "myCertificateInstallation" request has subject with "province" value "Utah"
    And task named "myCertificateInstallation" request has subject with "organization" value "Venafi Inc"
    And task named "myCertificateInstallation" request has subject with "orgUnits" value "engineering,marketing"
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has request with nickname based on commonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "cert.cer", chain name "chain.cer", key name "key.pem" with password, installation, validation and uses backup
    And task named "myCertificateInstallation" has installation format JKS with cert name "cert.jks", jksAlias "venafi" and jksPassword "foobar123" with installation
    And task named "myCertificateInstallation" has installation format PKCS12 with cert name "cert.p12" and password "Passcode123!" with installation
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully executed after-install actions"
    And the output should contain "successfully executed installation validation actions"
    And the output should contain "playbook run finished"
    And a file named "cert.cer" should exist
    And a file named "chain.cer" should exist
    And a file named "key.pem" should exist
    And a file named "cert.jks" should exist
    And a file named "cert.jks" should exist
    And a file named "cert.p12" should exist
    And playbook generated private key in "key.pem" and certificate in "cert.cer" should have the same modulus with password Passcode123!
    And playbook generated "cert.p12" should be PKCS#12 archive with password "Passcode123!"
    And "cert.p12" should be PKCS#12 archive with password "Passcode123!"
    # And "cert.jks" should be jks archive with password "foobar123" # TODO: solve this case
    And I uninstall file named "cert.cer"
    And I uninstall file named "chain.cer"
    And I uninstall file named "key.pem"
    And I uninstall file named "cert.jks"
    And I uninstall file named "cert.p12"

    Examples:
    | config-file      |
    | playbook-tpp.yml |

  Scenario Outline: Run playbook with default configuration, perform simple PEM installation and validates private key
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "local"
    And task named "myCertificateInstallation" has request with default "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem"
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus
    And "k1.pem" should not be encrypted "RSA" private key
    And "k1.pem" should be RSA private key with password ""
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"


    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  Scenario Outline: Run playbook with default configuration, perform simple PEM installation and validates encrypted private key
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "service"
    And task named "myCertificateInstallation" has request with default "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem" with password
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus with password Passcode123!
    And "k1.pem" should be encrypted "RSA" private key
    And "k1.pem" should be RSA private key with password "Passcode123!"
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  Scenario Outline: Run playbook with default configuration with local generated, perform simple PEM installation and validates encrypted private key
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "local"
    And task named "myCertificateInstallation" has request with default "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem" with password
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus with password Passcode123!
    And "k1.pem" should be encrypted "RSA" private key
    And "k1.pem" should be RSA private key with password "Passcode123!"
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  # This scenario takes into account you are running a Zone that creates a cert with validity more than 31d
  Scenario Outline: Run playbook twice with default configuration, perform simple PEM installation. Should prevent second issue
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "local"
    And task named "myCertificateInstallation" has request with default "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem"
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And I run `vcert run -f <config-file>`
    Then the output should contain "certificate in good health. No actions needed"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus
    And "k1.pem" should not be encrypted "RSA" private key
    And "k1.pem" should be RSA private key with password ""
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  Scenario Outline: Run playbook twice with default configuration, perform simple PEM installation. Should issue twice
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "local"
    And task named "myCertificateInstallation" has request with "validDays" value "30"
    And task named "myCertificateInstallation" has request with "issuerHint" value "MICROSOFT"
    And task named "myCertificateInstallation" has request with default "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem"
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus
    And "k1.pem" should not be encrypted "RSA" private key
    And "k1.pem" should be RSA private key with password ""
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  # This scenario takes into account you are running a Zone that creates a cert with validity more than 31d
  Scenario Outline: Run playbook twice with default configuration and --force-renew flag, perform simple PEM installation. Should issue twice
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "local"
    And task named "myCertificateInstallation" has request with default "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem"
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And I run `vcert run -f <config-file> --force-renew`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus
    And "k1.pem" should not be encrypted "RSA" private key
    And "k1.pem" should be RSA private key with password ""
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  Scenario Outline: Run playbook with default configuration, perform two tasks, each one doing PEM and PKCS12 installations respectively
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "service"
    And task named "myCertificateInstallation" has request with default "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem" with password
    And I have playbook with task named "myCertificateInstallationPKCS12"
    And task named "myCertificateInstallationPKCS12" has renewBefore with value "31d"
    And task named "myCertificateInstallationPKCS12" has request
    And task named "myCertificateInstallationPKCS12" has request with "csr" value "service"
    And task named "myCertificateInstallationPKCS12" has request with default "<platform>" zone
    And task named "myCertificateInstallationPKCS12" request has subject
    And task named "myCertificateInstallationPKCS12" request has subject with default values
    And task named "myCertificateInstallationPKCS12" request has subject random CommonName
    And task named "myCertificateInstallationPKCS12" has installations
    And task named "myCertificateInstallationPKCS12" has installation format PKCS12 with cert name "cert.p12" and password "Passcode124!" with validation
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And a file named "cert.p12" should exist
    And playbook generated private key in "k1.pem" and certificate in "c1.cer" should have the same modulus with password Passcode123!
    And "k1.pem" should be encrypted "RSA" private key
    And "k1.pem" should be RSA private key with password "Passcode123!"
    And playbook generated "cert.p12" should be PKCS#12 archive with password "Passcode124!"
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"
    And I uninstall file named "cert.p12"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  Scenario Outline: Run playbook with default configuration and performs PEM installation using service generated ECDSA private keys
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "service"
    And task named "myCertificateInstallation" has request with "keyType" value "ECDSA"
    And task named "myCertificateInstallation" has request with "keyCurve" value "P521"
    And task named "myCertificateInstallation" has request with default Elliptic Curve "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName with random site name and fixed Domain Name "vfidev.com"
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem"
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And "k1.pem" should not be encrypted "ECDSA" private key
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |

  Scenario Outline: Run playbook with default configuration and performs PEM installation using service generated encrypted ECDSA private keys
    Given I have playbook with <platform> connection details
    And I have playbook with certificateTasks block
    And I have playbook with task named "myCertificateInstallation"
    And task named "myCertificateInstallation" has renewBefore with value "31d"
    And task named "myCertificateInstallation" has request
    And task named "myCertificateInstallation" has request with "csr" value "service"
    And task named "myCertificateInstallation" has request with "keyType" value "ECDSA"
    And task named "myCertificateInstallation" has request with "keyCurve" value "P521"
    And task named "myCertificateInstallation" has request with default Elliptic Curve "<platform>" zone
    And task named "myCertificateInstallation" request has subject
    And task named "myCertificateInstallation" request has subject with default values
    And task named "myCertificateInstallation" request has subject random CommonName with random site name and fixed Domain Name "vfidev.com"
    And task named "myCertificateInstallation" has installations
    And task named "myCertificateInstallation" has installation format PEM with file name "c1.cer", chain name "ch1.cer", key name "k1.pem" with password
    And I created playbook named "<config-file>" with previous content
    And I run `vcert run -f <config-file>`
    Then the output should contain "successfully installed certificate"
    And the output should contain "playbook run finished"
    And a file named "c1.cer" should exist
    And a file named "ch1.cer" should exist
    And a file named "k1.pem" should exist
    And "k1.pem" should be encrypted "ECDSA" private key
    And I uninstall file named "c1.cer"
    And I uninstall file named "ch1.cer"
    And I uninstall file named "k1.pem"

    @TPP
    Examples:
      | platform | config-file       |
      | TPP      | playbook-tpp.yml  |

    @VAAS
    Examples:
      | platform | config-file       |
      | VaaS     | playbook-vaas.yml |