#!/bin/bash

# How to install:
#     ln -s /root/projects/dcg_security-ipmi-ppix-extensions/ppix-script/src/main/script/ppix-script.sh /usr/local/bin/ppix-script

VERBOSE=0
RUN_IPMITOOL=yes
IPMITOOL_OUTPUT_FILE=/tmp/ipmitool.out
IPMITOOL_OUTPUT_STDIN=no
IPMITOOL_OUTPUT_TEXT=
declare -a IMPITOOL_EXTRA_ARGS

help_usage() {

  echo -e '
\e[1mUSAGE:\e[0m
\e[0m      ./ppix-script \e[4mCOMMAND\e[0m -H <\e[4mBMC_IPADDRESS\e[0m> -U <\e[4mBMC_USERNAME\e[0m> -P [\e[4mBMC_PASSWORD\e[0m] 

\e[1mCOMMANDS:\e[0m

            discovery                       Determines the status of TXT and dTPM features.
            enable-txt-dtpm                 Enables TXT and dTPM. 
            clear-dtpm                      Clears dTPM ownership. TPM 1.2 is disabled afterwards. 
            clear-activate-dtpm             Clears dTPM ownership. TPM 1.2 is enabled afterwards. TPM 2.0 is always enabled.
            clear-activate-dtpm-enable-txt  Full Refresh for TXT/dTPM: clears ownership, enables dTPM and enables TXT
            enable-txt-ptt                  Enables TXT and PTT
            clear-ptt                       Clears PTT ownership.
            clear-activate-ptt              Clears PTT ownership. PTT is enabled
            clear-activate-ptt-enable-txt   Full Refresh for TXT/PTT: clears ownership, enables PTT and enables TXT

\e[1mOPTIONS:\e[0m

            -H BMC_IPADDRESS              A valid BMC IP address. This is required
            -U BMC_USERNAME               Username is required
            -P BMC_PASSWORD               Password is optional. If not explicitly declared user will be prompted to provide it

'
#Run ipmitool command and parse output:
#   ppix-script args
#Skip ipmitool command and parse predefined output:
#    ppix-script args < /path/to/output
#'
}

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

#
# input parameters: $1 - first hex number
#                   $2 - second hex number
get_features_supported() {
  local hex=$1$2
  #local hex=$1$2$3$4
  #local hex=0100

  # Convert to little endian, example: hex=034f, little endian = 4f03
  local hex_le
  local i=${#hex}

  while [ $i -gt 0 ]
  do
  	i=$[$i-2]
  	hex_le+=${hex:$i:2}
  done
  #echo "little_endian:"$hex_le
  
  # Once we have converted to little endian we parse the hex to decimal
  local dec=$((16#$hex_le))
  #echo "dec:"$dec

  # We apply a right shift on the least significant bit to eliminate it. 
  # We only care about the second and third least significan bits
  local rs=$(($dec>>1))
  #echo "rs:"$rs

  # We convert to binary
  local binary=$(echo "obase=2;$rs" | bc)
  #echo "binary:"$binary

  local j=${#binary}
  if [[ $j == 1 ]]; then
  	local bit1=${binary:$j-1:1}
    echo $bit1
  else
  	local bit1=${binary:$j-1:1}
  	local bit2=${binary:$j-2:1}
  	local bits=$bit2$bit1
  	echo $bits
  fi

}

# usage: is_bit_set <hex-value> <bit-number>
# return: 0 (true) if <bit-number> is set in <hex-value>, 1 (false) otherwise
# example: if is_bit_set FF 3; then echo "bit 3 of FF is set"; fi
# input parameters: $1 - first hex number
#                   $2 - second hex number
#                   $3 - bit position 
is_hex_bit_set() {
  local hex=$1$2
  #echo "hex:"$hex
  
  # Convert to little endian, example: hex=034f, little endian = 4f03
  local hex_le
  local i=${#hex}

  while [ $i -gt 0 ]
  do
  	i=$[$i-2]
  	hex_le+=${hex:$i:2}
  done
  
  local bitnum=$3
  # convert hex to decimal
  local dec=$((16#$hex_le))
  # convert bit number to a bitmask
  local mask=$((1<<$bitnum))
  # check bit: if set, result will be equal to mask; if not set, result will be zero
  local result=$(($dec & $mask))
  #echo "result:"$result
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
  #echo $array_name
  local array_offset=$2
  #echo $array_offset
  local expected_values=${@:3}
  #echo $expected_values
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
  local bmcipaddress=$3
  local username=$4
  local password=$5
  #echo "run_ipmitool:"$bmcipaddress
  #echo "run_ipmitool:"$username
  #echo "run_ipmitool:"$password
  local ipmitool_args=$($generator)
  if [ "$RUN_IPMITOOL" == "yes" ]; then
    local ipmitool_found=$(which ipmitool)
    if [ -z "$ipmitool_found" ]; then
      log_error "ipmitool not found"
      return 1
    fi
    #IMPITOOL_EXTRA_ARGS=$IMPITOOL_EXTRA_ARGS$" -I lanplus"
    #ipmitool $IMPITOOL_EXTRA_ARGS -b 0x06 -t 0x2c raw $ipmitool_args > $IPMITOOL_OUTPUT_FILE    

    local ipmi_args=$" -I lanplus -H "$bmcipaddress$" -U "$username

    if [ ! -z "$password" ]; then
    	ipmi_args=$ipmi_args$" -P "$password
    fi

    ipmitool $ipmi_args -b 0x06 -t 0x2c raw $ipmitool_args > $IPMITOOL_OUTPUT_FILE
    
  fi
  echo "Raw Request:"
  echo ""
  #echo ipmitool $IMPITOOL_EXTRA_ARGS -b 0x06 -t 0x2c raw $ipmitool_args
  echo $ipmitool_args
  echo ""

  # ipmitool output is space-separated hex values
  if [ "$IPMITOOL_OUTPUT_STDIN" == "yes" ]; then
    read_ssv_from_stdin_into_array IPMITOOL_OUTPUT_HEX
  else
    read_ssv_from_file_into_array $IPMITOOL_OUTPUT_FILE IPMITOOL_OUTPUT_HEX
  fi
  echo ""
  echo "Raw Response:"
  echo ""
  echo ${IPMITOOL_OUTPUT_HEX[@]}
  echo ""
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
  #echo "hex_array"
  #echo ${hex_array}
  DISCOVERY_OUTPUT=($hex_array)
  local intel=(57 01 00)
  local signature=(24 4f 58 50)
  local total_length=(20 00)
  local header_length=(20 00)
  local version=(01)
  local checksum
  local task_and_result
  local status
  #local password_attribute=(03 80)
  local password_attribute
  local feature_supported
  local feature_enabled
  #local state=(00 00 02 00)
  local state
  local i=0
  if values_required DISCOVERY_OUTPUT $i ${intel[@]}; then 
  	echo "Intel Manufacturer ID: Confirmed "${intel[@]}
  	((i+=${#intel[@]})); 
  else
    echo "Error. Manufacturer ID not supported" 
  	return 1; 
  fi

  #if values_required DISCOVERY_OUTPUT $i ${signature[@]}; then ((i+=${#signature[@]})); else return 1; fi
  signature=${DISCOVERY_OUTPUT[@]:$i:4}; ((i+=4))
  echo "Signature: "$signature

  if values_required DISCOVERY_OUTPUT $i ${total_length[@]}; then 
  	echo "Total Length(Decimal): "$((16#$total_length))
  	((i+=${#total_length[@]})); 
  else 
  	echo "Error. Total Length mismatch"
  	return 1; 
  fi

  if values_required DISCOVERY_OUTPUT $i ${header_length[@]}; then 
  	echo "Header Length(Decimal): "$((16#$header_length))
  	((i+=${#header_length[@]})); 
  else 
  	echo "Error. Header Length mismatch"
  	return 1; 
  fi
  if values_required DISCOVERY_OUTPUT $i ${version[@]}; then 
  	echo "Version: "$version
  	((i+=${#version[@]})); 
  else 
  	echo "Error. Version mismatch"
  	return 1; 
  fi

  checksum=${DISCOVERY_OUTPUT[$i]}; ((i+=1))
  echo "Checksum (Decimal): "$((16#$checksum))

  task_and_result=${DISCOVERY_OUTPUT[$i]}; ((i+=1))
  echo "Task and Result: "$task_and_result

  status=${DISCOVERY_OUTPUT[$i]}; ((i+=1))
  echo "Status: "$status
  #if values_required DISCOVERY_OUTPUT $i ${password_attribute[@]}; then ((i+=${#password_attribute[@]})); else return 1; fi
  
  #echo ${DISCOVERY_OUTPUT[@]:$i:2}

  password_attribute=${DISCOVERY_OUTPUT[@]:$i:2}; ((i+=2))
  feature_supported=${DISCOVERY_OUTPUT[@]:$i:2}; ((i+=2))
  feature_enabled=${DISCOVERY_OUTPUT[@]:$i:2}; ((i+=2))
  #if values_required DISCOVERY_OUTPUT $i ${state[@]}; then ((i+=${#state[@]})); else return 1; fi  
  state=${DISCOVERY_OUTPUT[@]:$i:4}; ((i+=4))
  log_debug_array feature_supported ${feature_supported[@]}
  log_debug_array feature_enabled ${feature_enabled[@]}
  local tpm_enabled="no"
  local ptt_enabled="no"

  #get_features_supported ${feature_enabled[0]}
  local result_supported=$(get_features_supported ${feature_supported[0]})
  echo   "TPM/TXT Support Status: "$result_supported
  case $result_supported in
  11)
    echo "                        dTPM, fTPM is supported"    
    ;;
  10)
    echo "                        fTPM is supported"
    ;;
  1|01)
    echo "                        dTPM is supported"
    ;;
  0|00)
    echo "                        TPM is NOT supported"
  esac

  if is_hex_bit_set ${feature_supported[0]} 0; then echo "                        TXT is supported"; else echo "                        TXT is NOT supported"; fi
  #if is_hex_bit_set ${feature_supported[0]} 1; then echo "TPM is supported"; else echo "TPM is not supported"; fi
  #if is_hex_bit_set ${feature_supported[0]} 2; then echo "PTT is supported"; else echo "PTT is not supported"; fi


  local result_enabled=$(get_features_supported ${feature_enabled[0]})
  echo   "TPM/TXT Enabled Status: "$result_enabled
  case $result_enabled in
  11)
    echo "                       Invalid configuration: dTPM and fTPM cannot be enabled concurrently"    
    ;;
  10)
    echo "                       fTPM is enabled"
    ;;
  1|01)
    echo "                       dTPM is enabled"
    ;;
  0|00)
    echo "                       TPM is NOT enabled"
  esac

  if is_hex_bit_set ${feature_enabled[0]} 0; then echo "                       TXT is enabled"; else echo "                       TXT is NOT enabled"; fi
  echo ""
  #if is_hex_bit_set ${feature_enabled[0]} 1; then echo "TPM is enabled"; tpm_enabled="yes"; else echo "TPM is not enabled"; fi
  #if is_hex_bit_set ${feature_enabled[0]} 2; then echo "PTT is enabled"; ptt_enabled="yes"; else echo "PTT is not enabled"; fi
  #if [ "$tpm_enabled" == "yes" ] && [ "$ptt_enabled" == "yes" ]; then
  #  log_error "invalid configuration: TPM and PTT cannot be enabled concurrently"
  #fi
}

write_enable_txt_tpm() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 a2 03 ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}

parse_enable_txt_tpm() {
  local hex_array=$@
  DISCOVERY_OUTPUT=($hex_array)
  local intel=(57 01 00)
  local i=0
  if values_required DISCOVERY_OUTPUT $i ${intel[@]}; then 
  	echo "Command execution is success"
  	((i+=${#intel[@]})); 
  else
    echo "Error: Manufacturer ID not supported" 
  	return 1; 
  fi
  local digest
  digest=(${DISCOVERY_OUTPUT[@]:$i:32}); ((i+=32))
  log_debug_array digest ${digest[@]}
}

write_clear_tpm() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 a1 04 ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}

write_clear_activate_tpm() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 a0 05 ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}

write_clear_activate_tpm_enable_txt() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 9f 06 ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}

write_enable_txt_ptt() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 9A 0b ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}

write_clear_ptt() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 99 0c ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}

write_clear_activate_ptt() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 98 0d ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}

write_clear_activate_ptt_enable_txt() {
  format_hex_array_with_0x 2e 91
  format_hex_array_with_0x 57 01 00
  format_hex_array_with_0x 00
  format_hex_array_with_0x 00 00 00
  format_hex_array_with_0x 01
  format_hex_array_with_0x 20 00 00 00

  format_hex_array_with_0x 24 4f 58 50 20 00 20 00 01 97 0e ff 00 00 00 00
  format_hex_array_with_0x 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
}


parse_raw_response() {
  local hex_array=$@
  RAW_OUTPUT=($hex_array)
  local intel=(57 01 00)
  local i=0
  if values_required RAW_OUTPUT $i ${intel[@]}; then
    echo "Command execution is success" 
  	((i+=${#intel[@]})); 
  else 
  	echo "Error: Manufacturer ID not supported"
  	return 1; 
  fi
  local digest
  digest=(${RAW_OUTPUT[@]:$i:32}); ((i+=32))
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
arg=$1
shift
case $arg in
  discovery)
    #Usecase 1 - TPM/TXT status discovery
    echo "discovery"
    generator=write_discovery
    parser=parse_discovery    
    ;;
  enable-txt-dtpm)
	#Usecase 2 - Enable TXT/ TPM
    echo "enable-txt-tpm"
    generator=write_enable_txt_tpm
    parser=parse_enable_txt_tpm    
    ;;
  clear-dtpm)
	#Usecase 3 - TPM Owner Clear Only
    echo "clear-tpm"
    generator=write_clear_tpm
    parser=parse_raw_response
    ;;
  clear-activate-dtpm)
	#Usecase 4 - TPM clear + TPM Activation
    echo "clear-activate-tpm"
    generator=write_clear_activate_tpm
    parser=parse_raw_response
    ;;
  clear-activate-dtpm-enable-txt)
	#Usecase 5 - TPM clear + TXT/TPM Activation
    echo "clear-activate-tpm-enable-txt"
    generator=write_clear_activate_tpm_enable_txt
    parser=parse_raw_response
    ;;
  enable-txt-ptt)
	#Usecase 6 - Enable TXT/PTT
    echo "enable-txt-ptt"
    generator=write_enable_txt_ptt
    parser=parse_raw_response
    ;;
  clear-ptt)
    #Usecase 7 - PTT  Owner Clear only
    echo "clear-ptt"
    generator=write_clear_ptt
    parser=parse_raw_response
    ;;
  clear-activate-ptt)
    echo "clear-activate-ptt"
    generator=write_clear_activate_ptt
    parser=parse_raw_response
    ;;
  clear-activate-ptt-enable-txt)
    echo "clear-activate-ptt-enable-txt"
    generator=write_clear_activate_ptt_enable_txt
    parser=parse_raw_response
    ;;
  -H)
    bmcipaddress=$1
    shift
    ;;
  -U)
    username=$1
    shift
    ;;
  -P)
    password=$1
    shift
    ;;
  #--)
  #  IMPITOOL_EXTRA_ARGS=("$@")
  #  break
  #  ;;
  *)
    help_usage
    exit 1
    ;;
esac

done

if [ "$IPMITOOL_OUTPUT_STDIN" == "no" ]; then
  #if [ ! -z "$generator" ] && [ ! -z "$parser" ] && [ ! -z "$IMPITOOL_EXTRA_ARGS" ]; then
  if [ ! -z "$generator" ] && [ ! -z "$parser" ] && [ ! -z "$bmcipaddress" ] && [ ! -z "$username" ]; then
    #run_impitool $generator $parser
    run_impitool $generator $parser $bmcipaddress $username $password
  else
    help_usage
    exit 1
  fi
else
	if [ ! -z "$generator" ] && [ ! -z "$parser" ] && [ ! -t 0 ]; then
	  run_impitool $generator $parser
	else
	  help_usage
	  exit 1
	fi
fi