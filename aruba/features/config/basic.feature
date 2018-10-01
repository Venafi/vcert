Feature: -config option

  As a user I want to use -config option which allows storing endpoint connection details in INI file

  (1) Config file may contain either TPP or Cloud or test-mode connection configuration

      TPP configuration example:

        tpp_url = https://ha-tpp1.venafi.example.com:5008/vedsdk
        tpp_user = user
        tpp_password = xxx
        tpp_zone = devops\vcert
        trust_bundle = ~/.vcert/6.23.crt

      Cloud configuration example:

        cloud_url = https://api.venafi.example.com/v1
        cloud_apikey = xxxxxxxx-b256-4c43-a4d4-15372ce2d548
        cloud_zone = Default

      Test-mode configuration example:

        test_mode = true

  (2) Only above examples' keys are allowed

  (3) If -config option is used, the following options are not allowed:

      -tpp-url
      -tpp-user
      -tpp-password
      -venafi-saas-url
      -k
      -test-mode

  (3.1) however, the following options are allowed and do override INI-file configuration values:

      -z
      -trust-bundle

  (4) There may be many [section]-s in INI-configuration file:

        [ha-tpp1]
        tpp_url = https://ha-tpp1.venafi.example.com:5008/vedsdk
        tpp_user = user
        tpp_password = xxx
        tpp_zone = devops\vcert
        trust_bundle = ~/.vcert/6.23.crt

        [dev12]
        cloud_url = https://dev12.venafi.example.com/v1
        cloud_apikey = xxxxxxxx-b256-4c43-a4d4-15372ce2d548
        cloud_zone = Default

        [mock]
        test_mode = true

      Each configuration section may be referenced by -profile option

        $ vCert enroll -cn w1.venafi.example.com -config all.ini -profile ha-tpp1

        $ vCert enroll -cn w1.venafi.example.com -config all.ini -profile dev12

        $ vCert enroll -cn w1.venafi.example.com -config all.ini -profile mock

      Empty sections are not valid, however, they are allowed if there are more than one section in INI file.


  Background:
    Given the default aruba exit timeout is 180 seconds

  Scenario: Simple enroll with -config test.ini
    Given a file named "test.ini" with:
    """
    test_mode = true
    """
    When I try to run `vcert enroll -config test.ini -cn cfg.venafi.example.com -no-prompt -z xxx`
    Then it should post certificate request
      And it should retrieve certificate

  Scenario: Where it returns error if ini-file doesn't exist
    When I try to run `vcert enroll -config does-not-exist.ini -cn cfg.venafi.example.com -no-prompt`
    Then it should fail with "failed to load config"

  Scenario: Where it returns error when ini-file is empty
    Given an empty file named "empty.ini"
    When I try to run `vcert enroll -config empty.ini -cn cfg.venafi.example.com -no-prompt`
    Then it should fail with "looks empty"

  Scenario: Where it returns error when ini-file contains both TPP and Cloud connection details
    Given a file named "mixed.ini" with:
    """
    tpp_url = https://tpp.venafi.example.com/
    tpp_user = user
    tpp_password = xxx
    tpp_zone = devops\vcert
    cloud_apikey = xxxxxxxx-b256-4c43-a4d4-15372ce2d548
    """
    When I try to run `vcert enroll -config mixed.ini -cn cfg.venafi.example.com -no-prompt`
    Then it should fail with "illegal key 'cloud_apikey'"

  Scenario: Where it returns error when TPP configuration doesn't contain user
    Given a file named "incomplete.ini" with:
    """
    tpp_url = https://tpp.venafi.example.com/
    # tpp_user = user
    tpp_password = xxx
    tpp_zone = devops\vcert
    """
    When I try to run `vcert enroll -config incomplete.ini -cn cfg.venafi.example.com -no-prompt`
    Then it should fail with "missing TPP user"

  Scenario: Where it returns error when TPP configuration doesn't contain password
    Given a file named "incomplete.ini" with:
    """
    tpp_url = https://tpp.venafi.example.com/
    tpp_user = user
    # tpp_password = xxx
    tpp_zone = devops\vcert
    """
    When I try to run `vcert enroll -config incomplete.ini -cn cfg.venafi.example.com -no-prompt`
    Then it should fail with "missing TPP password"


