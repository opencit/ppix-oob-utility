#!/bin/bash

# with sample responses:

ota discovery -- $@ < discovery.out.txt
ota enable-txt-tpm -- $@ < enable-txt-tpm.out.txt

# with ipmitool:

ota discovery -- $@
ota enable-txt-tpm -- $@
ota clear-tpm -- $@
ota clear-activate-tpm -- $@
ota clear-activate-tpm-enable-txt -- $@
ota status-tpm -- $@
ota enable-txt-ptt -- $@
ota clear-ptt -- $@
ota clear-activate-ptt -- $@
ota clear-activate-ptt-enable-txt -- $@
ota disable-txt -- $@
