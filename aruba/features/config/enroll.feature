Feature: Enrolling certificates with -config option

  As a user, I want my new -config option to be working with `enroll` action with TPP, Cloud and Test-mode endpoints

  Background:
    Given the default aruba exit timeout is 180 seconds
    And I have file named "tpp.ini" with TPP connection details
    And I have file named "tpp-deprecated.ini" with TPPdeprecated connection details
    And I have file named "test.ini" with test-mode connection details
    And I have file named "cloud.ini" with Cloud connection details
    And I have file named "ngts.ini" with NGTS connection details

  Scenario Outline: Where it enrolls a certificate using different endpoints
    When I try to run `vcert enroll -config <config-file> -cn cfg.venafi.example.com -no-prompt -insecure`
    Then it should retrieve certificate

    @FAKE
    Examples:
      | config-file |
      | test.ini    |

    @TPP
    Examples:
      | config-file |
      | tpp.ini     |
      # VC-55786: legacy /vedsdk/Authorize/ endpoint (username+password auth) was removed in TPP 26.1;
      # tpp-deprecated.ini exercises only that endpoint, so it can no longer enroll. Row disabled.
      # |tpp-deprecated.ini|

    @VAAS
    Examples:
      | config-file |
      | cloud.ini   |

    @NGTS
    Examples:
      | config-file |
      | ngts.ini   |
