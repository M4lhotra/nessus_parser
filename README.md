# nessus_parser
Python script to parse .nessus files and create an excel report. 

# Description
A simple script to parse one or multiple .nessus files and create a single excel report with all the consolidated findings. This script will parse all the nessus files provided and remove the findings with severity 'None'. 
The parser will merge all the cells which have the same finding names and different IPs or Ports. It will also automatically remove any duplicates found in the input file. 

# Requirements
`pip install xlsxwriter`

# Examples

Output file name is a mandatory argument to use this parser. The script will add the extension .xlsx
To supply a single nessus file use the argument '-f'

`./nessus_parser.py -f "./scan_info.nessus" -o "excel.report"`

OR

Store all .nessus files in a single folder and supply the path to folder as input using '-p'.

`./nessus_parser.py -p "/path_to_folder" -o "excel.report"`

# Features

+ Creates 3 sheets - Scope, Vulnerability Count and Vulnerability details.
+ Scope will give unquie IP address list, hostname and OS info from input files. 
+ Vulnerability count has count of each severity for different IPs. Excel formulas have already been added to the count so that it automatically gets updated when any false positives are removed from the Vulnerability details sheet. 
+ Vulnerability details sheet contains information about the vulnerability including IP, port, description and output from the scan results which provides path or version number of the component in question. 
