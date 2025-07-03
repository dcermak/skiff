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

  Scenario: Analyze image from podman storage
    Given I run podman pull registry.suse.com/bci/bci-busybox@sha256:1836fcf5e2ea1efab8cec4e8ffb1f8eb088224046ad6028043e4c5a028f5f2c3
    Then the exit code is 0
    Given I run skiff with the subcommand "layers containers-storage:registry.suse.com/bci/bci-busybox@sha256:1836fcf5e2ea1efab8cec4e8ffb1f8eb088224046ad6028043e4c5a028f5f2c3"
    Then the exit code is 0
    And stdout is
      """
      sha256:f9a8512c80bc65b2cd19d340333bc066beae246409c047560353b0eb9711bcb5 5586595
      """
