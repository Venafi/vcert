Feature: Enrolling certificates with -config option

  As a user, I want my new -config option to be working with `enroll` action with TPP, Cloud and Test-mode endpoints

  Background:
    Given the default aruba exit timeout is 180 seconds
    And I have file named "tpp.ini" with TPP connection details
    And I have file named "test.ini" with test-mode connection details
    And I have file named "cloud.ini" with Cloud connection details

  Scenario Outline: Where it enrolls a certificate using different endpoints
    When I try to run `vcert enroll -config <config-file> -cn cfg.venafi.example.com -no-prompt -insecure`
    Then it should retrieve certificate
    Examples:
      | config-file |
      | test.ini    |
      | tpp.ini     |
      | cloud.ini   |
