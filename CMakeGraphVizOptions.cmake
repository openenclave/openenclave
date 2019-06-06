# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# List of regular expressions matching targets to be excluded from the
# generated graph visual.
#
# See `docs/GettingStartedDocs/AdvancedBuildInfo`.

set(GRAPHVIZ_IGNORE_TARGETS
  "^test_"
  "test-support$"
  "_enc$"
  "_enc_unsigned$"
  "_enc_exported$"
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
  "^safemath$")
