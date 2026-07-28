Feature: `skiff diff` command

  Scenario: Run `skiff diff` without any arguments
    Given I run skiff with the subcommand "diff"
    Then the exit code is 1
    And stderr is
      """
      both image references are required
      """

  Scenario: Run `skiff diff` with only one image argument
    Given I run skiff with the subcommand "diff registry.suse.com/bci/bci-busybox:15.6.33.3"
    Then the exit code is 1
    And stderr is
      """
      both image references are required
      """

  Scenario: Compare two different busybox images with human-readable output
    Given I run skiff with the subcommand "diff --human-readable registry.suse.com/bci/bci-busybox:15.6.33.3 registry.suse.com/bci/bci-busybox:15.6.33.1"
    Then the exit code is 0
    And stdout is
      """
      Change    Size Diff  Path
      MODIFIED  -320 B     /usr/lib/sysimage/rpm/Packages.db
      MODIFIED  -39 B      /usr/share/busybox/busybox.links
      """

  Scenario: Compare two different busybox images without human-readable output
    Given I run skiff with the subcommand "diff registry.suse.com/bci/bci-busybox:15.6.33.3 registry.suse.com/bci/bci-busybox:15.6.33.1"
    Then the exit code is 0
    And stdout is
      """
      Change    Size Diff  Path
      MODIFIED  -320       /usr/lib/sysimage/rpm/Packages.db
      MODIFIED  -39        /usr/share/busybox/busybox.links
      """

  Scenario: Compare images with non-existent first image
    Given I run skiff with the subcommand "diff nonexistent:image registry.suse.com/bci/bci-busybox:15.6.33.3"
    Then the exit code is 1
    And stderr is
      """
      failed to load first image: reading manifest image in docker.io/library/nonexistent: requested access to the resource is denied
      """

  Scenario: Compare images with non-existent second image
    Given I run skiff with the subcommand "diff registry.suse.com/bci/bci-busybox:15.6.33.3 nonexistent:image"
    Then the exit code is 1
    And stderr is
      """
      failed to load second image: reading manifest image in docker.io/library/nonexistent: requested access to the resource is denied
      """

  Scenario: Compare identical images (should show no differences)
    Given I run skiff with the subcommand "diff registry.suse.com/bci/bci-busybox:15.6.33.3 registry.suse.com/bci/bci-busybox:15.6.33.3"
    Then the exit code is 0
    And stdout is
      """
      No differences found between the images.
      """ 