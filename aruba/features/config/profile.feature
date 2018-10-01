Feature: -profile option

  Using -profile option I want to specify a configuration profile to be used from INI-configuration file providede by -config option

  Background:
    Given the default aruba exit timeout is 180 seconds
    And I have file named "all.ini" with all endpoints connection details

  Scenario Outline: Where it enrolls a certificate using different profiles
    When I try to run `vcert enroll -config all.ini -profile <profile> -cn cfg.venafi.example.com -no-prompt -insecure`
    Then it should retrieve certificate
    Examples:
      | profile         |
      | mock-profile    |
      | tpp-profile     |
      | cloud-profile   |
