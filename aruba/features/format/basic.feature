Feature: -format output option

  As a user
  I want the output to be in different formats. Default is PEM.

  Scenario: where it outputs error if unknown format is used
    When I enroll random certificate in test-mode with -no-prompt -format xxx
    Then it should fail with "Unexpected output format"
