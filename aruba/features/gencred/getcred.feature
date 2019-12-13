Feature: Getting credentials tokens from TPP

  As a user
  I want to get credentials tokens from TPP

  Background:
    Given the default aruba exit timeout is 180 seconds

  Scenario: request refresh token
    When I get tokens from TPP
    Then it should output access token
      And it should output refresh token

  Scenario: refresh access token
    When I refresh access token
    Then it should output access token
      And it should output refresh token