Feature: `skiff layers` command

  Scenario: Run `skiff layers` without any commands
    Given I run skiff with the subcommand "layers"
    Then the exit code is 1
    And stderr contains
      """
      image URL is required
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
    And stdout contains
      """
      sha256:abb83fe2605d91490ec6d6812c2fec309feb463e4359f8f971428bb560c38af1 47480531
      sha256:dbdff6b3e29778a160277784fbcfc864cf1e0c6df77edbac2bafb777c16b77b6 46534194
      """
