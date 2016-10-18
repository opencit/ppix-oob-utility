#!/bin/bash

# with sample responses:

ppix-script discovery < discovery.out.txt
ppix-script enable-txt-tpm < enable-txt-tpm.out.txt

# with ipmitool:

ppix-script discovery
ppix-script enable-txt-tpm
ppix-script clear-tpm
ppix-script clear-activate-tpm
ppix-script clear-activate-tpm-enable-txt
ppix-script status-tpm
ppix-script enable-txt-ptt
ppix-script clear-ptt
ppix-script clear-activate-ptt
ppix-script clear-activate-ptt-enable-txt
ppix-script disable-txt
