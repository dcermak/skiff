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
         --full-digest, --full-diff-id\s+Show full digests instead of truncated \(12 chars\) \(default: false\)
         --help, -h\s+show help
      """

  Scenario: Analyze an image from a registry
    Given I run podman rmi registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f --ignore
    And I run skiff with the subcommand "layers registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      Diff ID       Compressed Size
      4672d0cba723  47480531
      88304527ded0  46534194
      """

  Scenario: Analyze a local image pulled from the registry with an explicit containers-storage transport
    Given I run podman pull registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f
    And I run skiff with the subcommand "layers containers-storage:registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      Diff ID       Uncompressed Size
      4672d0cba723  125604864
      88304527ded0  129486336
      """

  Scenario: Analyze image from podman storage
    Given I run podman pull ghcr.io/github/github-mcp-server@sha256:0c720d3b8aab0e5107a2631516543095c6967637b52b8782dc9ee527a0803012
    Then the exit code is 0
    Given I run skiff with the subcommand "layers ghcr.io/github/github-mcp-server@sha256:0c720d3b8aab0e5107a2631516543095c6967637b52b8782dc9ee527a0803012"
    Then the exit code is 0
    And stdout is
      """
      Diff ID       Uncompressed Size
      f464af4b9b25  327680
      8fa10c0194df  40960
      48c0fb67386e  2406400
      114dde0fefeb  102400
      4d049f83d9cf  1536
      af5aa97ebe6c  2560
      6f1cdceb6a31  2560
      bbb6cacb8c82  2560
      2a92d6ac9e4f  1536
      1a73b54f556b  10240
      f4aee9e53c42  3072
      bfe9137a1b04  241664
      d5a3e014161b  13056000
      2e4983c761ce  5918720
      76dbf54073c9  1536
      2c8b3de21aa2  13228544
      """

  Scenario: Analyze an image from a registry with full digests
    Given I run podman rmi registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f --ignore
    And I run skiff with the subcommand "layers --full-digest registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      Diff ID                                                                  Compressed Size
      sha256:4672d0cba723f1a9a7b91c1e06f5d8801a076b1bdf4990806cdaabcd53992738  47480531
      sha256:88304527ded0288579ec4780fe377a7fabc5bc92f965c18e9ee734a8bb1794bb  46534194
      """

  Scenario: Analyze an image with full digests
    Given I run skiff with the subcommand "layers --full-diff-id registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      Diff ID                                                                  Compressed Size
      sha256:4672d0cba723f1a9a7b91c1e06f5d8801a076b1bdf4990806cdaabcd53992738  47480531
      sha256:88304527ded0288579ec4780fe377a7fabc5bc92f965c18e9ee734a8bb1794bb  46534194
      """
