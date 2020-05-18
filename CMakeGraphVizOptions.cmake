# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# List of regular expressions matching targets to be excluded from the
# generated graph visual.
#
# See `docs/GettingStartedDocs/AdvancedBuildInfo`.

set(GRAPHVIZ_IGNORE_TARGETS
    "^test_"
    "test-support$"
    "test-support-lvi-cfg$"
    "_enc$"
    "_enc-lvi-cfg$"
    "_enc_unsigned$"
    "_enc_unsigned-lvi-cfg$"
    "_enc_exported$"
    "_enc_exported-lvi-cfg$"
    "_host$"
    "^libmbedtest"
    "^mbedtest_"
    "^SampleApp"
    "^pingpong-"
    "^str$"
    "^aesm$"
    "^cryptohost$"
    "^hostcrypto$"
    "^cryptoenc$"
    "^mem$"
    "^safemath$"
    "^crypto$"
    "^crypto-lvi-cfg$"
    "^dl$"
    "^dl-lvi-cfg$")
