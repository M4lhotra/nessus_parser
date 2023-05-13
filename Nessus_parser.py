#!/usr/bin/python

import argparse
import xlsxwriter
import xml.etree.ElementTree as ET
import glob

#Arguments

parser = argparse.ArgumentParser(description='''Data parser from a single or multiple .nessus files.
example: nessus_parser.py -f filename.nessus -o output_file_name
OR
example: nessus_parser.py -p path_to_folder -o output_file_name
''')
required_args = parser.add_argument_group('required arguments')
required_args.add_argument('-o', '--output', type=str, help='Output filename is required. The script will add .xlsx extension.', required=True)

group = required_args.add_mutually_exclusive_group(required=True)
group.add_argument('-f', '--filename', metavar='path', type=str, help='Either provide .nessus file name with this argument.')
group.add_argument('-p', '--path', metavar='path', type=str, help=' Provide the path to folder with multiple .nessus files. ')
args = parser.parse_args()

findings = []

workbook = xlsxwriter.Workbook(args.output + '.xlsx')

#Check how many arguments have been given.
if args.filename:
    files = glob.glob(args.filename)
elif args.path:
    folder = args.path + "/*.nessus"
    files = glob.glob(folder)

#Parsing data from files one by one. 
print("Parsing data from nessus files ......")
for file in files:
    tree = ET.parse(file)

    #Parsing information related to the host.
    for host in tree.findall('Report/ReportHost'):
        ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text
        if host.find("HostProperties/tag/[@name='hostname']") is not None:
            hostname = host.find("HostProperties/tag/[@name='hostname']").text
        else:
            hostname = ipaddr
        if host.find("HostProperties/tag/[@name='operating-system']") is not None:
            os = host.find("HostProperties/tag/[@name='operating-system']").text
        else:
            os = "N/A"
        
        for item in host.findall('ReportItem'):
            if item.find('risk_factor') is not None:
                risk_factor = item.find('risk_factor').text
            else:
                risk_factor = "None"
            pluginID = item.get('pluginID')
            pluginName = item.get('pluginName')
            pluginFamily = item.get('pluginFamily')
            if item.find('description') is not None:
                description = item.find('description').text
            else:
                description = "None"
            if item.find('synopsis') is not None:
                synopsis = item.find('synopsis').text
            else:
                synopsis = "None"
            if item.find('solution') is not None:
                solution = item.find('solution').text
            else:
                solution = "None"
            if item.find('plugin_output') is not None:
                output = item.find('plugin_output').text
            else:
                output = "None"
            if item.find('see_also') is not None:
                references = item.find('see_also').text
            else:
                references = "None"
            port = item.get('port')
            protocol = item.get('protocol')
            severity = item.find('severity')
            if severity is not None:
                print(severity)
            itera = [ipaddr, port, hostname, risk_factor, pluginName, description, solution, synopsis, output, references, os, pluginFamily]
            #Remove findings with severity as None.
            if (itera[3] != "None"):
                findings.append(itera)
        #Create a set with name of the findings to remove any duplicates. 
        pname = set()
        name = list()
        for x in range(len(findings)):
            pname.add((findings[x][4]))
        #Create a list name back from the set pname which has all the unique findings. 
        name = list(pname)

new_list = [list(t) for t in set(tuple(l) for l in findings)]
findings = new_list
findings_dct = {}
for x in range(len(name)):
    findings_dct[name[x]] = []
#Write all the findings in a dictionary with the finding names as the keys
for x in range(len(findings)):
    for y in range(len(name)):
        if name[y] == findings[x][4]:
            findings_dct[name[y]].append(findings[x])

# We already have the finding name as keys. We dont need to write it twice so delete that value from our dictionary.
for key in findings_dct.keys():
    for value in findings_dct[key]:
        del value[4]


print("Parsing completed.")
print("Writing Data in excel file.")

#Defining cell formats for different cells
heading = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#063970', 'font_size': 14, 'border': 1})
finding_format = workbook.add_format({'border': 1})
low_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#00D31F', 'border': 1,'align':'center'})
medium_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#EFA600', 'border': 1,'align':'center'})
high_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#FF0000', 'border': 1,'align':'center'})
critical_format = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#BD0000', 'border': 1,'align':'center'})
total_format = workbook.add_format({'bold': True, 'border':1, 'align':'center'})
critical_heading = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#BD0000', 'font_size': 14, 'border': 1})
high_heading = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#FF0000', 'font_size': 14, 'border': 1})
medium_heading = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#EFA600', 'font_size': 14, 'border': 1})
low_heading = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#00D31F', 'font_size': 14, 'border': 1})


#Defining worksheets
scope = workbook.add_worksheet("Scope")
counting = workbook.add_worksheet("Vulnerability Count")
details = workbook.add_worksheet("Vulnerability Details")

#Set the width for different columns
scope.set_column(1,1,15)
scope.set_column(2,2,25)
scope.set_column(3,3,50)
details.set_column(0,0,5)
details.set_column(6,11,35)
details.set_column(11,11,15)
details.set_column(1,1,35)
details.set_column(4,4,15)
details.set_column(2,2,15)
counting.set_column(1,1,20)

#Write the headings for cells
scope.write(1, 1, "IP address", heading)
scope.write(1, 2, "Hostname", heading)
scope.write(1, 3, "Operating System", heading)
details.write(1, 0, "SNo.", heading)
details.write(1, 1, "Finding Name", heading)
details.write(1, 2, "IP Address",heading)
details.write(1, 3, "Port", heading)
details.write(1, 4, "Hostname", heading)
details.write(1, 5, "Severity",heading)
details.write(1, 6, "Description",heading)
details.write(1, 7, "Solution", heading)
details.write(1, 8, "Synopsis", heading)
details.write(1, 9, "Output",heading)
details.write(1, 10, "References",heading)
details.write(1, 11, "OS",heading)
details.write(1, 12, "Category", heading)
counting.write(1,1,"IP Address",heading)
counting.write(1,2,"Critical",critical_heading)
counting.write(1,3,"High",high_heading)
counting.write(1,4,"Medium",medium_heading)
counting.write(1,5,"Low",low_heading)
counting.write(1,6,"Total",heading)

#Filling information in the scope sheet.
row = 2
temp_ips = []

for x in findings:
    if x[0] not in temp_ips:
        temp_ips.append(x[0])
for index in temp_ips:
    column = 1
    for i in range(len(findings)):
        if index == findings[i][0]:
            scope.write(row,column,findings[i][0],finding_format)
            counting.write(row,column,findings[i][0],finding_format)
            counting.write(row,2,'''=COUNTIFS('Vulnerability details'!$C:$C,'Vulnerability Count'!$B'''+str(row+1)+''','Vulnerability details'!$F:$F,"Critical")''',finding_format)            
            counting.write(row,3,'''=COUNTIFS('Vulnerability details'!$C:$C,'Vulnerability Count'!$B'''+str(row+1)+''','Vulnerability details'!$F:$F,"High")''',finding_format)
            counting.write(row,4,'''=COUNTIFS('Vulnerability details'!$C:$C,'Vulnerability Count'!$B'''+str(row+1)+''','Vulnerability details'!$F:$F,"Medium")''',finding_format)
            counting.write(row,5,'''=COUNTIFS('Vulnerability details'!$C:$C,'Vulnerability Count'!$B'''+str(row+1)+''','Vulnerability details'!$F:$F,"Low")''',finding_format)
            counting.write(row,6,'''=SUM($C'''+str(row+1)+''':$F'''+str(row+1)+''')''',finding_format)
            scope.write(row,column+1,findings[i][2],finding_format)
            scope.write(row,column+2,findings[i][9],finding_format)
    row += 1

row = 2

#Filling information in the Vulnerability details sheet. 
for x in findings_dct.keys():
    column = 0
    details.write(row,column+1,x,finding_format)
    last_value = row
    for y in findings_dct[x]:
        for i in range(len(y)):
            if y[i] == "High":
                details.write(row,column,row-1,finding_format)
                details.write(row,column+(i+2),y[i],high_format)
            elif y[i] == "Medium":
                details.write(row,column,row-1,finding_format)
                details.write(row,column+(i+2),y[i],medium_format)
            elif y[i] == "Low":
                details.write(row,column,row-1,finding_format)
                details.write(row,column+(i+2),y[i],low_format)
            else:
                details.write(row,column,row-1,finding_format)
                details.write(row,column+(i+2),y[i],finding_format)                     
        row += 1

    #Merge empty cells in the findings column. 
    if last_value != row-1:
        details.merge_range(last_value, 1, row-1, 1, '')

print("File " + args.output + ".xlsx is ready.")
workbook.close()
