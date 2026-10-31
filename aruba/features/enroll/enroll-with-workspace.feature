Feature: enrolling certificates scoped to an NGTS workspace

  As a user
  I want to enroll certificates within a specific NGTS workspace
  So that the certificate is created in the workspace my team owns

  Background:
    And the default aruba exit timeout is 180 seconds

  Scenario Outline: where it enrolls a certificate in a workspace
    When I enroll a random certificate in <endpoint> with -no-prompt
    Then the output should contain "Successfully posted request"

    @NGTS
    Examples:
      | endpoint      |
      | NGTSworkspace |

  Scenario Outline: where it rejects a workspace on a platform that does not support one
    When I enroll a random certificate in <endpoint> with -no-prompt --workspace 1234567890
    Then the exit status should not be 0
    And the output should contain "--workspace is only applicable to Palo Alto Networks Next-Gen Trust Security (NGTS)"

    @TPP
    Examples:
      | endpoint |
      | TPP      |

    @VAAS
    Examples:
      | endpoint |
      | Cloud    |

  Scenario Outline: where it rejects a workspace name given instead of a workspace ID
    When I enroll a random certificate in <endpoint> with -no-prompt --workspace not-an-id
    Then the exit status should not be 0
    And the output should contain "A workspace is identified by its numeric ID, not its name"

    @NGTS
    Examples:
      | endpoint |
      | NGTS     |
