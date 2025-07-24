Feature: `skiff top` command

  Scenario: Run `skiff top` without any arguments
    Given I run skiff with the subcommand "top"
    Then the exit code is 1
    And stderr contains
      """
      image URL is required
      """

  Scenario: Analyze an actual image with top command
    Given I run skiff with the subcommand "top registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     LAYER ID
      /usr/bin/container-suseconnect     9245304  abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1     8767504  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  7837536  dbdff6b3e297
      /usr/lib64/libpython3.11.so.1.0    5876440  dbdff6b3e297
      /usr/lib64/libcrypto.so.3.1.4      5715672  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  5190128  abb83fe2605d
      /usr/share/misc/magic.mgc          4983184  abb83fe2605d
      /usr/lib/git/git                   3726520  dbdff6b3e297
      /usr/lib/locale/locale-archive     3058640  abb83fe2605d
      /usr/bin/zypper                    2915456  abb83fe2605d
      """

  Scenario: Use --layer flag without specifying layer digest
    Given I run skiff with the subcommand "top --layer registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 1
    And stderr contains
      """
      image URL is required
      """

  Scenario: Filter by single layer using full digest
    Given I run skiff with the subcommand "top --layer abb83fe2605d registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     LAYER ID
      /usr/bin/container-suseconnect     9245304  abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1     8767504  abb83fe2605d
      /usr/lib64/libcrypto.so.3.1.4      5715672  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  5190128  abb83fe2605d
      /usr/share/misc/magic.mgc          4983184  abb83fe2605d
      /usr/lib/locale/locale-archive     3058640  abb83fe2605d
      /usr/bin/zypper                    2915456  abb83fe2605d
      /lib64/libc.so.6                   2449832  abb83fe2605d
      /usr/lib64/libstdc++.so.6.0.33     2424040  abb83fe2605d
      /usr/lib64/ossl-modules/fips.so    2285504  abb83fe2605d
      """

  Scenario: Filter by single layer using partial digest
    Given I run skiff with the subcommand "top --layer abb83 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     LAYER ID
      /usr/bin/container-suseconnect     9245304  abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1     8767504  abb83fe2605d
      /usr/lib64/libcrypto.so.3.1.4      5715672  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  5190128  abb83fe2605d
      /usr/share/misc/magic.mgc          4983184  abb83fe2605d
      /usr/lib/locale/locale-archive     3058640  abb83fe2605d
      /usr/bin/zypper                    2915456  abb83fe2605d
      /lib64/libc.so.6                   2449832  abb83fe2605d
      /usr/lib64/libstdc++.so.6.0.33     2424040  abb83fe2605d
      /usr/lib64/ossl-modules/fips.so    2285504  abb83fe2605d
      """

  Scenario: Filter by single layer using full digest (dbdff6b3e297)
    Given I run skiff with the subcommand "top --layer dbdff6b3e297 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     LAYER ID
      /usr/lib/sysimage/rpm/Packages.db  7837536  dbdff6b3e297
      /usr/lib64/libpython3.11.so.1.0    5876440  dbdff6b3e297
      /usr/lib/git/git                   3726520  dbdff6b3e297
      /usr/lib/sysimage/rpm/Index.db     2756608  dbdff6b3e297
      /usr/lib/git/git-remote-http       2191584  dbdff6b3e297
      /usr/lib/git/git-http-push         2187352  dbdff6b3e297
      /usr/lib/git/git-imap-send         2183704  dbdff6b3e297
      /usr/lib/git/scalar                2183136  dbdff6b3e297
      /usr/lib/git/git-http-fetch        2175096  dbdff6b3e297
      /usr/lib/git/git-http-backend      2142032  dbdff6b3e297
      """

  Scenario: Filter by multiple layers
    Given I run skiff with the subcommand "top --layer abb83fe2605d --layer dbdff6b3e297 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE     LAYER ID
      /usr/bin/container-suseconnect     9245304  abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1     8767504  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  7837536  dbdff6b3e297
      /usr/lib64/libpython3.11.so.1.0    5876440  dbdff6b3e297
      /usr/lib64/libcrypto.so.3.1.4      5715672  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  5190128  abb83fe2605d
      /usr/share/misc/magic.mgc          4983184  abb83fe2605d
      /usr/lib/git/git                   3726520  dbdff6b3e297
      /usr/lib/locale/locale-archive     3058640  abb83fe2605d
      /usr/bin/zypper                    2915456  abb83fe2605d
      """

  Scenario: Filter by non-existent layer
    Given I run skiff with the subcommand "top --layer nonexistentlayer registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 1
    And stderr contains
      """
      layer nonexistentlayer not found in image
      """

  Scenario: Use --layer with short flag alias
    Given I run skiff with the subcommand "top -l abb83fe2605d registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout contains "abb83fe2605d"
    And stdout does not contain "dbdff6b3e297"

  Scenario: Use --layer with multiple short flag aliases
    Given I run skiff with the subcommand "top -l abb83fe2605d -l dbdff6b3e297 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout contains "abb83fe2605d"
    And stdout contains "dbdff6b3e297"

  Scenario: Use --layer with empty string
    Given I run skiff with the subcommand "top --layer '' registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 1
    And stderr contains
      """
      multiple layers match shortened digest
      """

  Scenario: Use --human-readable flag for human-readable file sizes
    Given I run skiff with the subcommand "top --human-readable registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE    LAYER ID
      /usr/bin/container-suseconnect     9.2 MB  abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1     8.8 MB  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  7.8 MB  dbdff6b3e297
      /usr/lib64/libpython3.11.so.1.0    5.9 MB  dbdff6b3e297
      /usr/lib64/libcrypto.so.3.1.4      5.7 MB  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  5.2 MB  abb83fe2605d
      /usr/share/misc/magic.mgc          5.0 MB  abb83fe2605d
      /usr/lib/git/git                   3.7 MB  dbdff6b3e297
      /usr/lib/locale/locale-archive     3.1 MB  abb83fe2605d
      /usr/bin/zypper                    2.9 MB  abb83fe2605d
      """

  Scenario: Use --human-readable with layer filtering
    Given I run skiff with the subcommand "top --human-readable --layer abb83fe2605d registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE    LAYER ID
      /usr/bin/container-suseconnect     9.2 MB  abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1     8.8 MB  abb83fe2605d
      /usr/lib64/libcrypto.so.3.1.4      5.7 MB  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  5.2 MB  abb83fe2605d
      /usr/share/misc/magic.mgc          5.0 MB  abb83fe2605d
      /usr/lib/locale/locale-archive     3.1 MB  abb83fe2605d
      /usr/bin/zypper                    2.9 MB  abb83fe2605d
      /lib64/libc.so.6                   2.4 MB  abb83fe2605d
      /usr/lib64/libstdc++.so.6.0.33     2.4 MB  abb83fe2605d
      /usr/lib64/ossl-modules/fips.so    2.3 MB  abb83fe2605d
      """

  Scenario: Use --human-readable with multiple layer filtering
    Given I run skiff with the subcommand "top --human-readable --layer abb83fe2605d --layer dbdff6b3e297 registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      FILE PATH                          SIZE    LAYER ID
      /usr/bin/container-suseconnect     9.2 MB  abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1     8.8 MB  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  7.8 MB  dbdff6b3e297
      /usr/lib64/libpython3.11.so.1.0    5.9 MB  dbdff6b3e297
      /usr/lib64/libcrypto.so.3.1.4      5.7 MB  abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db  5.2 MB  abb83fe2605d
      /usr/share/misc/magic.mgc          5.0 MB  abb83fe2605d
      /usr/lib/git/git                   3.7 MB  dbdff6b3e297
      /usr/lib/locale/locale-archive     3.1 MB  abb83fe2605d
      /usr/bin/zypper                    2.9 MB  abb83fe2605d
      """

  Scenario: Use --human-readable with short flag alias
    Given I run skiff with the subcommand "top -h registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout contains "MB"
    And stdout does not contain "9245304"