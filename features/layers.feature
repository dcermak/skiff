Feature: `skiff layers` command

  Scenario: Run `skiff layers` without any commands
    Given I run skiff with the subcommand "layers"
    Then the exit code is 1
    And stderr contains
      """
      sufficient count of arg url not provided
      """

  Scenario: Run `skiff layers --help`
    Given I run skiff with the subcommand "layers --help"
    Then the exit code is 0
    And stdout contains
      """
      skiff layers - Print the size of each layer in an image.
      """
    And stdout contains
      """
      OPTIONS:
         --help, -h\s+show help
      """

  Scenario: Analyze an actual image
    Given I run skiff with the subcommand "layers registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      """
