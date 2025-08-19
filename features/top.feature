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
      File Path                        	   Size	Layer ID
      -------------------------------------------------------------------
      /usr/bin/container-suseconnect   	9245304	abb83fe2605d
      /usr/lib64/libzypp.so.1735.1.1   	8767504	abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db	7837536	dbdff6b3e297
      /usr/lib64/libpython3.11.so.1.0  	5876440	dbdff6b3e297
      /usr/lib64/libcrypto.so.3.1.4    	5715672	abb83fe2605d
      /usr/lib/sysimage/rpm/Packages.db	5190128	abb83fe2605d
      /usr/share/misc/magic.mgc        	4983184	abb83fe2605d
      /usr/lib/git/git                 	3726520	dbdff6b3e297
      /usr/lib/locale/locale-archive   	3058640	abb83fe2605d
      /usr/bin/zypper                  	2915456	abb83fe2605d
      """

  Scenario: Analyze an image from containers-storage with top command
    Given I run podman pull registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f
    Then the exit code is 0
    Given I run skiff with the subcommand "top containers-storage:registry.suse.com/bci/python@sha256:677b52cc1d587ff72430f1b607343a3d1f88b15a9bbd999601554ff303d6774f"
    Then the exit code is 0
    And stdout is
      """
      File Path                        	   Size	Layer ID
      -------------------------------------------------------------------
      /usr/bin/container-suseconnect   	9245304	4672d0cba723
      /usr/lib64/libzypp.so.1735.1.1   	8767504	4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db	7837536	88304527ded0
      /usr/lib64/libpython3.11.so.1.0  	5876440	88304527ded0
      /usr/lib64/libcrypto.so.3.1.4    	5715672	4672d0cba723
      /usr/lib/sysimage/rpm/Packages.db	5190128	4672d0cba723
      /usr/share/misc/magic.mgc        	4983184	4672d0cba723
      /usr/lib/git/git                 	3726520	88304527ded0
      /usr/lib/locale/locale-archive   	3058640	4672d0cba723
      /usr/bin/zypper                  	2915456	4672d0cba723
      """
