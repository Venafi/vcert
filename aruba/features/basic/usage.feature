Feature: Showing usage text page

  As a user
  I want to see usage text

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario: Usage text
    When I run `vcert`
    Then the output should contain:
      """
      For additional help run
      """

  Scenario: Enroll help text
    When I run `vcert enroll -h`
    Then the output should contain:
      """
      Enrollment Usage
      """