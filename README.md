#OTA Utility

OTA (One Touch Activation) Utility is  extension script to open source IPMITOOL which allows system admin to input the PPIx OOB hex codes in human readable verbose format and decode the response to human readable format.

**Servers supported:**


- Intel&reg; Skylake based servers and onwards


**Requirements:**
  


- Linux VM or host
- IPMItool (open source BSD license)
- BMC enabled Intel&reg; Skylake server




**How to use:**




1. Clone or download the repository from github and execute the following command in your IPMItool enabled VM:


	ln -s <your_github_repository_location>/ppix-script/src/main/script/ota.sh /usr/local/bin/ota

2. Make sure you have bc package installed:
	
	bc -version

	In case this package is missing install it in your VM. For Ubuntu the command is as follows:

	sudo apt-get install bc
	


1. Now yo can execute the available commands provided:

			
			discovery						Determines the status of TXT and dTPM features.
			enable-txt-dtpm 				Enables TXT and dTPM
            clear-dtpm                      Clears dTPM ownership. TPM 1.2 is disabled afterwards.
            clear-activate-dtpm             Clears dTPM ownership. TPM 1.2 is enabled afterwards. TPM 2.0 is always enabled.
            clear-activate-dtpm-enable-txt  Full Refresh for TXT/dTPM: clears ownership, enables dTPM and enables TXT
            enable-txt-ptt                  Enables TXT and PTT
            clear-ptt                       Clears PTT ownership.
            clear-activate-ptt              Clears PTT ownership. PTT is enabled
            clear-activate-ptt-enable-txt   Full Refresh for TXT/PTT: clears ownership, enables PTT and enables TXT
            disable-txt                     Disables TXT only
            disable-dtpm                    Disables dTPM only. This will not disable TXT
            disable-ptt                     Disables PTT

For example, to run discovery:

	ota discovery -H "BMC IP address" -U username -P password
