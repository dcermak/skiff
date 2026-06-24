Feature: `skiff rpm-diff` command

  Scenario: Diff two pinned SLE15 BCI image tags
    Given I run skiff with the subcommand "rpm-diff --new-image=registry.suse.com/suse/sle15:15.7-5.20.19 --old-image=registry.suse.com/suse/sle15:15.7-5.17.9"
    Then the exit code is 0
    And stdout contains
      """
        \+ libsubid5 \[x86_64\] \(sles/sles-15\.7\) 4\.17\.2-150600\.17\.18\.1
      """
    And stdout contains
      """
        ~ libfdisk1 \[x86_64\] \(sles/sles-15\.7\)
              version: 2\.40\.4-150700\.4\.3\.1 -> 2\.40\.4-150700\.4\.10\.1
      """
    And stdout contains
      """
        ~ liblzma5 \[x86_64\] \(sles/sles-15\.7\)
              version: 5\.4\.1-150600\.3\.3\.1 -> 5\.4\.1-150600\.3\.6\.1
              license: SUSE-Public-Domain -> LicenseRef-SUSE-Public-Domain
      """
    And stdout contains
      """
        ~ timezone \[x86_64\] \(sles/sles-15\.7\)
              version: 2025b-150600\.91\.6\.2 -> 2026b-150600\.91\.9\.1
              size: 1312057 -> 1317547
              license: BSD-3-Clause AND SUSE-Public-Domain -> BSD-3-Clause AND LicenseRef-SUSE-Public-Domain
      """
