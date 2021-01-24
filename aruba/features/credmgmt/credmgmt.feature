Feature: Managing credentials tokens from TPP

  As a user
  I want to get, check, and void credentials (tokens) from TPP

  Background:
    Given the default aruba exit timeout is 180 seconds

  Scenario: request refresh token and refresh access token
    When I get credentials from TPP
    And I remember the output
      And it should output access token
      And it should output refresh token
    Then I refresh access token
      And I remember the output
      And it should output access token
      And it should output refresh token

  Scenario: request refresh token in json format
    When I get credentials from TPP with -format json
      And I remember the output
      And it should output access token in JSON
      And it should output refresh token in JSON

  Scenario: request with PKCS12 if possible
    When I get credentials from TPP with PKSC12
    And I remember the output
      And it should output access token
      And it should output refresh token

  Scenario: request with PKCS12 if possible with no password
    When I interactively get credentials from TPP with PKSC12 and no password
    And I type "newPassw0rd!"
    And I remember the output
      And it should output access token
      And it should output refresh token

  Scenario: request refresh token and refresh access token with username and no password
    When I interactively get credentials from TPP with username and no password
    And I remember the output
      And it should output access token
      And it should output refresh token

  Scenario: check access token
    When I get credentials from TPP
    And I remember the output
      And it should output access token
    Then I check access token
    And I remember the output
      And it should output application
      And it should output expires
      And it should output scope

  Scenario: check token in json format
    When I get credentials from TPP with -format json
    And I remember the output
      And it should output access token in JSON
    Then I check access token with -format json
    And I remember the output
      And it should output application in JSON
      And it should output expires in JSON
      And it should output scope in JSON

  Scenario: void access token grant
    When I get credentials from TPP
    And I remember the output
      And it should output access token
    Then I void access token grant
    And I remember the output
      And it should output revoked
