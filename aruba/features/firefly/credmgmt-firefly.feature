@FIREFLY
Feature: Managing credentials tokens from Identity Providers

  As a user
  I want to get credentials for Firefly with Okta as IdP

  Background:
    Given the default aruba exit timeout is 180 seconds

  Scenario Outline: request access token from IdP
    When I get credentials from "<identity-provider>"
    And I remember the output
    And it should output access token

    Examples:
      | identity-provider |
      | Okta              |

  Scenario Outline: request access token from IdP in JSON format
    When I get credentials from "<identity-provider>" with -format json
    And I remember the output
    And it should output access token in JSON

    Examples:
      | identity-provider |
      | Okta              |

  Scenario Outline: request access token from IdP using password flow
    When I get credentials from "<identity-provider>" with username and password
    And I remember the output
    And it should output access token

    Examples:
      | identity-provider |
      | Okta              |

  @TODO # currently interactive mode is not working for Idp for Firefly
  Scenario Outline: request access token from IdP using password flow interactively
    When I interactively get credentials from "<identity-provider>" with username and no password
    And I remember the output
    And it should output access token

    Examples:
      | identity-provider |
      | Okta              |