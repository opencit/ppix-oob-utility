#!/bin/bash

# How to install:
#     ln -s /root/projects/dcg_security-ipmi-ppix-extensions/ppix-script/src/main/script/ppix-script.sh /usr/local/bin/ppix-script

VERBOSE=0
RUN_IPMITOOL=yes
IPMITOOL_OUTPUT_FILE=/tmp/ipmitool.out
IPMITOOL_OUTPUT_STDIN=no
IPMITOOL_OUTPUT_TEXT=

help_usage() {
  echo '
Run ipmitool command and parse output:
    ppix-script args
Skip ipmitool command and parse predefined output:
    ppix-script args < /path/to/output
'
}

if [[ $# -eq 0 ]]; then
  help_usage
  return 1
fi

# precondition:
# * a file exists with space-separated values content
# * an array variable exists, declared with "declare -a <variable-name>"
# postcondition:
# * the specified array contains one item for each value in the file
read_ssv_from_file_into_array() {
  local file=$1
  local varname=$2
  local text=$(cat "$file")
  eval "$varname=($text)"
}

# precondition:
# * input is available on stdin with space-separated values content
# * an array variable exists, declared with "declare -a <variable-name>"
# postcondition:
# * the specified array contains one item for each value in stdin
read_ssv_from_stdin_into_array() {
  local varname=$1
  local text=$(cat)
  eval "$varname=($text)"
}

# usage: is_bit_set <hex-value> <bit-number>
# return: 0 (true) if <bit-number> is set in <hex-value>, 1 (false) otherwise
# example: if is_bit_set FF 3; then echo "bit 3 of FF is set"; fi
is_hex_bit_set() {
  local hex=$1
  local bitnum=$2
  # convert hex to decimal
  local dec=$((16#$hex))
  # convert bit number to a bitmask
  local mask=$((1<<$bitnum))
  # check bit: if set, result will be equal to mask; if not set, result will be zero
  local result=$(($dec & $mask))
  if [ $result -eq 0 ]; then return 1; fi
  return 0
}

# usage: values_present <array-name> <array-offset> <values...>
# return: 0 (true) if array-name contains the specified values starting at <array-offset>, 1 (false) otherwise
# example: myarray=(a b c)
#          if expect_values myarray 0 a b c; then echo "ok"; fi 
#          if expect_values myarray 1 b c; then echo "ok"; fi 
values_present() {
  local array_name=$1
  local array_offset=$2
  local expected_values=${@:3}
  local actual_values
  eval actual_values=(\${$array_name[@]})
  local actual  
  local expected
  for expected in ${expected_values[@]}
  do
    actual=${actual_values[$array_offset]}
    #echo "expected: $expected   vs   actual: $actual"
    if [ "$expected" != "$actual" ]; then
      return 1
    fi
    ((array_offset+=1))
  done
  return 0
}

values_required() {
  local array_name=$1
  local array_offset=$2
  local expected_values=${@:3}
  if values_present $array_name $array_offset ${expected_values[@]}; then
    return 0
  fi
  local actual_values
  eval actual_values=(\${$array_name[@]})
  log_error "mismatch at offset $array_offset: expected '${expected_values[@]}' found '${actual_values[@]}'"
  return 1
}

# usage:
# hex_array=(00 01 ff)
# dec_array=($(convert_hex_array_to_decimal_array ${hex_array[@]}))
# echo ${#dec_array[@]}   => 3
# echo ${dec_array[@]}   => 0 1 255
convert_hex_array_to_decimal_array() {
  local hex_arr=$@
  for hex in ${hex_arr[@]}
  do
    echo -n "$((16#$hex)) "
  done
}

# usage:
# hex_array=(00 01 ff)
# fmt_hex_array=($(format_hex_array_with_0x ${hex_array[@]}))
# echo ${#fmt_hex_array[@]}   => 3
# echo ${fmt_hex_array[@]}   => 0x00 0x01 0xff
format_hex_array_with_0x() {
  local hex_arr=$@
  for hex in ${hex_arr[@]}
  do
    echo -n "0x${hex} "
  done
}


# global variables:
# * RUN_IPMITOOL (in)
# * IPMITOOL_OUTPUT_STDIN (in)
# * IPMITOOL_OUTPUT_FILE (in)
# * IPMITOOL_OUTPUT_HEX (out)
run_impitool() {
  local generator=$1
  local parser=$2
  local ipmitool_args=$($generator)
  echo ipmitool -b 0x06 -t 0x2c raw $ipmitool_args
  if [ "$RUN_IPMITOOL" == "yes" ]; then
    local ipmitool_found=$(which ipmitool)
    if [ -z "$ipmitool_found" ]; then
      log_error "ipmitool not found"
      return 1
    fi
    ipmitool -b 0x06 -t 0x2c raw $ipmitool_args > $IPMITOOL_OUTPUT_FILE    
  fi
  # ipmitool output is space-separated hex values
  if [ "$IPMITOOL_OUTPUT_STDIN" == "yes" ]; then
    read_ssv_from_stdin_into_array IPMITOOL_OUTPUT_HEX
  else
    read_ssv_from_file_into_array $IPMITOOL_OUTPUT_FILE IPMITOOL_OUTPUT_HEX
  fi
  $parser ${IPMITOOL_OUTPUT_HEX[@]}
}

log_debug_array() {
  local array_name=$1
  local array_values=${@:2}
  if [[ $VERBOSE -gt 0 ]]; then
    echo "[DEBUG] array '$array_name': ${array_values[@]}"
  fi
}

log_error() {
  local message="$@"
  local TERM_COLOR_RED="\\033[1;31m"
  local TERM_COLOR_NORMAL="\\033[0;39m"
  echo -en "${TERM_COLOR_RED}"
  echo "$message" >&2
  echo -en "${TERM_COLOR_NORMAL}"
}

write_discovery() {
  format_hex_array_with_0x 2e 90 57 01 00 00 00 00 00 20
}

# global variables:
# * DISCOVERY_OUTPUT
# example:  parse_discovery 57 01 00 24 4f 58 50 20 00 20 00 01 79 80 01 03 80 23 00 02 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00
parse_discovery() {
  local hex_array=$@
  DISCOVERY_OUTPUT=($hex_array)
  local intel=(57 01 00)
  local signature=(24 4f 58 50)
  local total_length=(20 00)
  local header_length=(20 00)
  local version=(01)
  local checksum
  local task_and_result
  local status
  local password_attribute=(03 80)
  local feature_supported
  local feature_enabled
  local state=(00 00 02 00)
  local i=0
  if values_required DISCOVERY_OUTPUT $i ${intel[@]}; then ((i+=${#intel[@]})); else return 1; fi
  if values_required DISCOVERY_OUTPUT $i ${signature[@]}; then ((i+=${#signature[@]})); else return 1; fi
  if values_required DISCOVERY_OUTPUT $i ${total_length[@]}; then ((i+=${#total_length[@]})); else return 1; fi
  if values_required DISCOVERY_OUTPUT $i ${header_length[@]}; then ((i+=${#header_length[@]})); else return 1; fi
  if values_required DISCOVERY_OUTPUT $i ${version[@]}; then ((i+=${#version[@]})); else return 1; fi
  checksum=${DISCOVERY_OUTPUT[$i]}; ((i+=1))
  task_and_result=${DISCOVERY_OUTPUT[$i]}; ((i+=1))
  status=${DISCOVERY_OUTPUT[$i]}; ((i+=1))
  if values_required DISCOVERY_OUTPUT $i ${password_attribute[@]}; then ((i+=${#password_attribute[@]})); else return 1; fi
  feature_supported=(${DISCOVERY_OUTPUT[@]:$i:2}); ((i+=2))
  feature_enabled=(${DISCOVERY_OUTPUT[@]:$i:2}); ((i+=2))
  if values_required DISCOVERY_OUTPUT $i ${state[@]}; then ((i+=${#state[@]})); else return 1; fi  
  log_debug_array feature_supported ${feature_supported[@]}
  log_debug_array feature_enabled ${feature_enabled[@]}
  local tpm_enabled="no"
  local ptt_enabled="no"
  if is_hex_bit_set ${feature_supported[0]} 0; then echo "TXT is supported"; else echo "TXT is not supported"; fi
  if is_hex_bit_set ${feature_supported[0]} 1; then echo "TPM is supported"; else echo "TPM is not supported"; fi
  if is_hex_bit_set ${feature_supported[0]} 2; then echo "PTT is supported"; else echo "PTT is not supported"; fi
  if is_hex_bit_set ${feature_enabled[0]} 0; then echo "TXT is enabled"; else echo "TXT is not enabled"; fi
  if is_hex_bit_set ${feature_enabled[0]} 1; then echo "TPM is enabled"; tpm_enabled="yes"; else echo "TPM is not enabled"; fi
  if is_hex_bit_set ${feature_enabled[0]} 2; then echo "PTT is enabled"; ptt_enabled="yes"; else echo "PTT is not enabled"; fi
  if [ "$tpm_enabled" == "yes" ] && [ "$ptt_enabled" == "yes" ]; then
    log_error "invalid configuration: TPM and PTT cannot be enabled concurrently"
  fi
}

write_enable_txt_tpm() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 27 00 00 00

  format_hex_array_with_0x 24 4f 58 50 27 00 20 00 01
  format_hex_array_with_0x 29 03 ff
  format_hex_array_with_0x 00 00 00 00
  format_hex_array_with_0x 00 00 40 00 00 40 00 00 00 00 00 00 00 00 00 00
  format_hex_array_with_0x 01 07 00 01 80
  format_hex_array_with_0x 69 00
}

parse_enable_txt_tpm() {
  local hex_array=$@
  DISCOVERY_OUTPUT=($hex_array)
  local intel=(57 01 00)
  local i=0
  if values_required DISCOVERY_OUTPUT $i ${intel[@]}; then ((i+=${#intel[@]})); else return 1; fi
  local digest
  digest=(${DISCOVERY_OUTPUT[@]:$i:32}); ((i+=32))
  log_debug_array digest ${digest[@]}
}

# check if there is input from stdin
# example:  ppix-script discovery < /path/to/test.file
if [ ! -t 0 ]; then
  RUN_IPMITOOL=no
  IPMITOOL_OUTPUT_STDIN="yes"
fi

while [[ $# -gt 0 ]]
do
case $1 in
  discovery)
    echo "discovery"
    run_impitool write_discovery parse_discovery
    ;;
  enable-txt-tpm)
    echo "enable-txt-tpm"
    run_impitool write_enable_txt_tpm parse_enable_txt_tpm
    ;;
  clear-tpm)
    echo "clear-tpm"
    #run_impitool write_clear_tpm parse_clear_tpm
    ;;
  clear-activate-tpm)
    echo "clear-activate-tpm"
    #run_impitool write_activate_tpm parse_activate_tpm
    ;;
  clear-activate-tpm-enable-txt)
    echo "clear-activate-tpm-enable-txt"
    #run_ipmitool ...
    ;;
  status-tpm)
    echo "status-tpm"
    #run_ipmitool ...
    ;;
  enable-txt-ptt)
    echo "enable-txt-ptt"
    #run_ipmitool ...
    ;;
  clear-ptt)
    echo "clear-ptt"
    #run_ipmitool ...
    ;;
  clear-activate-ptt)
    echo "clear-activate-ptt"
    #run_ipmitool ...
    ;;
  clear-activate-ptt-enable-txt)
    echo "clear-activate-ptt-enable-txt"
    #run_ipmitool ...
    ;;
  disable-txt)
    echo "disable-txt"
    #run_ipmitool ...
    ;;
  *)
    help_usage
    exit 1
    ;;
esac
shift
done
