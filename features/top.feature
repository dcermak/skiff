Feature: `skiff top` command

  Scenario: Run `skiff top` without any arguments
    Given I run skiff with the subcommand "top"
    Then the exit code is 1
    And stderr contains
      """
      image URL is required
      """

  Scenario: Analyze an actual image with top command
    Given I run podman rmi registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f --ignore
    And I run skiff with the subcommand "top registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     DIFF ID
      /usr/bin/container-suseconnect     9245304  4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1     8767504  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  7837536  88304527ded0
      /usr/lib64/libpython3.11.so.1.0    5876440  88304527ded0
      /usr/lib64/libcrypto.so.3.1.4      5715672  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  5190128  4672d0cba723
      /usr/share/misc/magic.mgc          4983184  4672d0cba723
      /usr/lib/git/git                   3726520  88304527ded0
      /usr/lib/locale/locale-archive     3058640  4672d0cba723
      /usr/bin/zypper                    2915456  4672d0cba723
      """

  Scenario: Analyze an image from containers-storage with top command
    Given I run podman pull registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f
    Then the exit code is 0
    Given I run skiff with the subcommand "top containers-storage:registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     DIFF ID
      /usr/bin/container-suseconnect     9245304  4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1     8767504  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  7837536  88304527ded0
      /usr/lib64/libpython3.11.so.1.0    5876440  88304527ded0
      /usr/lib64/libcrypto.so.3.1.4      5715672  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  5190128  4672d0cba723
      /usr/share/misc/magic.mgc          4983184  4672d0cba723
      /usr/lib/git/git                   3726520  88304527ded0
      /usr/lib/locale/locale-archive     3058640  4672d0cba723
      /usr/bin/zypper                    2915456  4672d0cba723
      """

  Scenario: Filter by single layer using partial digest
    Given I run skiff with the subcommand "top --layer 4672d0 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     DIFF ID
      /usr/bin/container-suseconnect     9245304  4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1     8767504  4672d0cba723
      /usr/lib64/libcrypto.so.3.1.4      5715672  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  5190128  4672d0cba723
      /usr/share/misc/magic.mgc          4983184  4672d0cba723
      /usr/lib/locale/locale-archive     3058640  4672d0cba723
      /usr/bin/zypper                    2915456  4672d0cba723
      /lib64/libc.so.6                   2449832  4672d0cba723
      /usr/lib64/libstdc++.so.6.0.33     2424040  4672d0cba723
      /usr/lib64/ossl-modules/fips.so    2285504  4672d0cba723
      """

  Scenario: Filter by multiple layers
    Given I run skiff with the subcommand "top --layer 4672d0cba723 --layer 88304527ded0 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     DIFF ID
      /usr/bin/container-suseconnect     9245304  4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1     8767504  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  7837536  88304527ded0
      /usr/lib64/libpython3.11.so.1.0    5876440  88304527ded0
      /usr/lib64/libcrypto.so.3.1.4      5715672  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  5190128  4672d0cba723
      /usr/share/misc/magic.mgc          4983184  4672d0cba723
      /usr/lib/git/git                   3726520  88304527ded0
      /usr/lib/locale/locale-archive     3058640  4672d0cba723
      /usr/bin/zypper                    2915456  4672d0cba723
      """

  Scenario: Filter by non-existent layer
    Given I run skiff with the subcommand "top --layer nonexistentlayer registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 1
    And stderr contains
      """
      diffID nonexistentlayer not found in image
      """

  Scenario: Use --human-readable flag for human-readable file sizes
    Given I run skiff with the subcommand "top --human-readable registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE    DIFF ID
      /usr/bin/container-suseconnect     9.2 MB  4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1     8.8 MB  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  7.8 MB  88304527ded0
      /usr/lib64/libpython3.11.so.1.0    5.9 MB  88304527ded0
      /usr/lib64/libcrypto.so.3.1.4      5.7 MB  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  5.2 MB  4672d0cba723
      /usr/share/misc/magic.mgc          5.0 MB  4672d0cba723
      /usr/lib/git/git                   3.7 MB  88304527ded0
      /usr/lib/locale/locale-archive     3.1 MB  4672d0cba723
      /usr/bin/zypper                    2.9 MB  4672d0cba723
      """

  Scenario: Use --human-readable with layer filtering
    Given I run skiff with the subcommand "top --human-readable --layer 4672d0cba723 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE    DIFF ID
      /usr/bin/container-suseconnect     9.2 MB  4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1     8.8 MB  4672d0cba723
      /usr/lib64/libcrypto.so.3.1.4      5.7 MB  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  5.2 MB  4672d0cba723
      /usr/share/misc/magic.mgc          5.0 MB  4672d0cba723
      /usr/lib/locale/locale-archive     3.1 MB  4672d0cba723
      /usr/bin/zypper                    2.9 MB  4672d0cba723
      /lib64/libc.so.6                   2.4 MB  4672d0cba723
      /usr/lib64/libstdc++.so.6.0.33     2.4 MB  4672d0cba723
      /usr/lib64/ossl-modules/fips.so    2.3 MB  4672d0cba723
      """

  Scenario: Use --human-readable with multiple layer filtering
    Given I run skiff with the subcommand "top --human-readable --layer 4672d0cba723 --layer 88304527ded0 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE    DIFF ID
      /usr/bin/container-suseconnect     9.2 MB  4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1     8.8 MB  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  7.8 MB  88304527ded0
      /usr/lib64/libpython3.11.so.1.0    5.9 MB  88304527ded0
      /usr/lib64/libcrypto.so.3.1.4      5.7 MB  4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db  5.2 MB  4672d0cba723
      /usr/share/misc/magic.mgc          5.0 MB  4672d0cba723
      /usr/lib/git/git                   3.7 MB  88304527ded0
      /usr/lib/locale/locale-archive     3.1 MB  4672d0cba723
      /usr/bin/zypper                    2.9 MB  4672d0cba723
      """
