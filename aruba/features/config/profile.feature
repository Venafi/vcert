Feature: -profile option

  Using -profile option I want to specify a configuration profile to be used from INI-configuration file provided by -config option

  Background:
    Given the default aruba exit timeout is 180 seconds
    And I have file named "all.ini" with all endpoints connection details

  Scenario Outline: Where it enrolls a certificate using different profiles
    When I enroll random certificate -config "all.ini" -profile <profile> with -no-prompt -insecure
    Then it should retrieve certificate

    @FAKE
    Examples:
      | profile         |
      | mock-profile    |

    @TPP
    Examples:
      | profile         |
      | tpp-profile     |

    @VAAS
    Examples:
      | profile         |
      | cloud-profile   |
