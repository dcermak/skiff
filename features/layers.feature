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
    Given I run podman rmi registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f --ignore
    And I run skiff with the subcommand "layers registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      Digest                                                                   Size
      sha256:abb83fe2605d91490ec6d6812c2fec309feb463e4359f8f971428bb560c38af1  47480531
      sha256:dbdff6b3e29778a160277784fbcfc864cf1e0c6df77edbac2bafb777c16b77b6  46534194
      """

  Scenario: Analyze a local image pulled from the registry with an explicit containers-storage transport
    Given I run podman pull registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f
    And I run skiff with the subcommand "layers containers-storage:registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      Digest                                                                   Size      Uncompressed Digest                                                      Uncompressed Size
      sha256:abb83fe2605d91490ec6d6812c2fec309feb463e4359f8f971428bb560c38af1  47480531  sha256:4672d0cba723f1a9a7b91c1e06f5d8801a076b1bdf4990806cdaabcd53992738  125604864
      sha256:dbdff6b3e29778a160277784fbcfc864cf1e0c6df77edbac2bafb777c16b77b6  46534194  sha256:88304527ded0288579ec4780fe377a7fabc5bc92f965c18e9ee734a8bb1794bb  129486336
      """

  Scenario: Analyze image from podman storage
    Given I run podman pull ghcr.io/github/github-mcp-server@sha256:0c720d3b8aab0e5107a2631516543095c6967637b52b8782dc9ee527a0803012
    Then the exit code is 0
    Given I run skiff with the subcommand "layers ghcr.io/github/github-mcp-server@sha256:0c720d3b8aab0e5107a2631516543095c6967637b52b8782dc9ee527a0803012"
    Then the exit code is 0
    And stdout is
      """
      Digest                                                                   Size     Uncompressed Digest                                                      Uncompressed Size
      sha256:35d697fe273816c60d20a62a879f8643f79cd4ed85a8e80dba28a17350fc26b6  104226   sha256:f464af4b9b251ebe8a7c2f186aff656f0892f6cb159837a6ce8fd63842e83e35  327680
      sha256:bfb59b82a9b65e47d485e53b3e815bca3b3e21a095bd0cb88ced9ac0b48062bf  13356    sha256:8fa10c0194df9b7c054c90dbe482585f768a54428fc90a5b78a0066a123b1bba  40960
      sha256:4eff9a62d888790350b2481ff4a4f38f9c94b3674d26b2f2c85ca39cdef43fd9  547593   sha256:48c0fb67386ed713921fcc0468be23231d0872fa67ccc8ea3929df4656b6ddfc  2406400
      sha256:62de241dac5fe19d5f8f4defe034289006ddaa0f2cca735db4718fe2a23e504e  31240    sha256:114dde0fefebbca13165d0da9c500a66190e497a82a53dcaabc3172d630be1e9  102400
      sha256:a62778643d563b511190663ef9a77c30d46d282facfdce4f3a7aecc03423c1f3  67       sha256:4d049f83d9cf21d1f5cc0e11deaf36df02790d0e60c1a3829538fb4b61685368  1536
      sha256:7c12895b777bcaa8ccae0605b4de635b68fc32d60fa08f421dc3818bf55ee212  188      sha256:af5aa97ebe6ce1604747ec1e21af7136ded391bcabe4acef882e718a87c86bcc  2560
      sha256:3214acf345c0cc6bbdb56b698a41ccdefc624a09d6beb0d38b5de0b2303ecaf4  123      sha256:6f1cdceb6a3146f0ccb986521156bef8a422cdbb0863396f7f751f575ba308f4  2560
      sha256:5664b15f108bf9436ce3312090a767300800edbbfd4511aa1a6d64357024d5dd  168      sha256:bbb6cacb8c82e4da4e8143e03351e939eab5e21ce0ef333c42e637af86c5217b  2560
      sha256:0bab15eea81d0fe6ab56ebf5fba14e02c4c1775a7f7436fbddd3505add4e18fa  93       sha256:2a92d6ac9e4fcc274d5168b217ca4458a9fec6f094ead68d99c77073f08caac1  1536
      sha256:4aa0ea1413d37a58615488592a0b827ea4b2e48fa5a77cf707d0e35f025e613f  385      sha256:1a73b54f556b477f0a8b939d13c504a3b4f4db71f7a09c63afbc10acb3de5849  10240
      sha256:da7816fa955ea24533c388143c78804c28682eef99b4ee3723b548c70148bba6  321      sha256:f4aee9e53c42a22ed82451218c3ea03d1eea8d6ca8fbe8eb4e950304ba8a8bb3  3072
      sha256:ddf74a63f7d8b7d157e5db1a45675a58e304b4c1d425b05c28c835b987623395  131927   sha256:bfe9137a1b044e8097cdfcb6899137a8a984ed70931ed1e8ef0cf7e023a139fc  241664
      sha256:d00c3209d92970dad10c006c4d7120e5fd276349ce6e57dbad95a3a3f05411fc  5830214  sha256:d5a3e014161bb602d87c2312e371ad2ea6f800c7f7af261af4faa67302b53c88  13056000
      sha256:c058825cfcd674180d54bec6822f5d549c038b3c66884c197a863341943c2e70  2827225  sha256:2e4983c761ce4933ecec23c31173fed551a237c8d0ba359b697de64bd953a7c3  5918720
      sha256:76a77595d36b90d9aa33d5e5a0aa1ebdd20cd1fcfdc1b222b0ae5e87e07d6999  96       sha256:76dbf54073c985e4093346f6d727fd937120392517defcc62d2c74a08ac839d0  1536
      sha256:d465ba56b0b6c90d59a717497d9ca64b16eabff92b7f463cf27febf9caaab3f5  4827257  sha256:2c8b3de21aa225aa567da7b5c81b991729ab63e9c329573880fb0e6b1687b7ed  13228544
      """
