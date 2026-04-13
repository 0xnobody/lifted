#!/bin/bash

SUITES=synthetic,tum-basic-algorithms,tum-small-programs,tum-simple-hash-functions,gnu-coreutils
EVAL=./build/src/lifted-eval/lifted-eval
CLI=./build/src/lifted-cli/lifted-cli

# EG1
$EVAL \
  --suite "$SUITES" \
  --obfuscator polaris \
  --without-mutation \
  --lift-timeout-sec 300 \
  --output-root eval/results

# EG1, EG2, EG3
$EVAL \
  --suite "$SUITES" \
  --obfuscator none \
  --without-standard \
  --with-mutation \
  --mutation-budget 200 \
  --mutation-seed 0x1337 \
  --lift-timeout-sec 300 \
  --output-root eval/results

# EG4
$CLI fn \
  --suite tum-basic-algorithms \
  --target numtowords \
  --func main \
  --no-full-pipeline \
  --max-deep-dives 0 \
  --output-dir eval/lifted-numtowords-case-study \
  --render-cfg pdf