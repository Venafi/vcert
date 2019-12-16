Feature: Getting credentials tokens from TPP

  As a user
  I want to get credentials tokens from TPP

  Background:
    Given the default aruba exit timeout is 180 seconds

  Scenario: request refresh token and refresh access token
    When I get tokens from TPP
      And I remember the output
      And it should output access token
      And it should output refresh token
    Then I refresh access token
      And I remember the output
      And it should output access token
      And it should output refresh token

  Scenario: request refresh token in json format
    When I get tokens from TPP with -format json
      And I remember the output
      And it should output access token in JSON
      And it should output refresh token in JSON