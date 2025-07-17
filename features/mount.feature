Feature: `skiff mount` command

  Scenario: Run `skiff mount` without any arguments
    Given I run skiff with the subcommand "mount"
    Then the exit code is 1
    And stderr contains
      """
      image URL is required
      """

  Scenario: Run `skiff mount` with only one argument
    Given I run skiff with the subcommand "mount registry.suse.com/bci/busybox:latest"
    Then the exit code is 1
    And stderr contains
      """
      mountpoint is required
      """

  Scenario: Mount Docker Hub busybox image and verify filesystem contents
    Given I create a temporary directory for mounting
    When I run skiff with the subcommand "mount docker://busybox:latest {temp_dir}" in the background
    When I wait for the background process to output "Mounted docker://busybox:latest at {temp_dir}" within 30 seconds
    When I run "ls {temp_dir}/"
    Then the exit code is 0
    When I run "ls {temp_dir}/bin/busybox"
    Then the exit code is 0
    When I quit the background process
