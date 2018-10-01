Feature: showing version

  As a user, I want to know version number of the app

  Scenario: where user asks for -version
    When I run `vcert -version`
    Then the output should contain:
    """
    Version: 3.18.3.1
    """
