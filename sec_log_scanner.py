import os
import csv
from datetime import date
import re as regex
from itertools import zip_longest

#specify the full log file directory and file here
path = os.path.join('C:\\Users\\kevin.fernandez\\Documents\\sample_logs', 'netlogon.log')

#open the file
with open(path, 'r') as f:
    log = f.readlines()

#iterate through the log and find unknown user name errors, append to list
unknown_user_name_errors = [] 
for entry in log:
    if '0xC0000064' in entry:
        unknown_user_name_errors.append(entry)

#extract the information needed from each entry
#Example: 06/01 16:03:13 [LOGON] [20004] DomainInitials: SamLogon: Network logon of Domain\ComputerName from ComputerName Returns 0xC0000064
uu_date_time = []
uu_computer_names = []
uu_error_numbers = []
for entry in unknown_user_name_errors:
    #gather error numbers and append to list
    uu_error_numbers.append(entry.split("Returns")[1])
    uu_error_numbers = [i.strip() for i in uu_error_numbers]   
    #gather computer names and append to list
    uu_computer_names.append(regex.search('from\ (.*?)\ Returns', entry).group(1))

    #gather date/time and append to list
    uu_date_time.append(entry.split("[")[0])

#iterate through the log and find bad password errors, append to list
#Example: 06/01 16:07:31 [LOGON] [19920] DomainInitials: SamLogon: Transitive Network logon of WNSM\first.lastname from  (via DC) Returns 0xC000006A
bad_password_errors = []
for entry in log:
    if '0xC000006A' in entry:
        bad_password_errors.append(entry)

print(bad_password_errors)
#extract the information needed from each entry
bp_date_time = []
bp_user_name = []
bp_error_numbers = []
for entry in bad_password_errors:
    #gather error numbers and append to list
    bp_error_numbers.append(entry.split("Returns")[1])
    bp_error_numbers = [i.strip() for i in bp_error_numbers]   
    print(bp_error_numbers)
    #gather computer names and append to list
    bp_user_name.append(regex.search('of\ (.*?)\ from', entry).group(1))

    #gather date/time and append to list
    bp_date_time.append(entry.split("[")[0])

#TO DO - ONCE I GET A FEW LOGS OF LOCKED OUT USERS I CAN UPDATE THE FIND EXPRESSION
#iterate through the log and find locked out errors, append to list
user_locked_errors = []
for entry in log:
    if '0xC0000234' in entry:
        user_locked_errors.append(entry)

#file formatting to input as rows in the columns
unknown_user_error_data = [uu_date_time, uu_computer_names, uu_error_numbers]
unknown_user_export_data = zip_longest(*unknown_user_error_data, fillvalue = '')
bad_password_error_data = [bp_date_time, bp_user_name, bp_error_numbers]
bad_password_export_data = zip_longest(*bad_password_error_data, fillvalue = '')

#name and open the file
today = date.today()
filename = f"NetLogon_flagged_errors_{str(today)}.csv"


#write the spreadsheet
with open(filename, 'w', encoding="ISO-8859-1", newline='') as myfile:
    wr = csv.writer(myfile)
    #write unknown user errors
    wr.writerow(["Unknown User Errors"])
    wr.writerow(("Date", "Computer Name", "Error"))
    wr.writerows(unknown_user_export_data)
    wr.writerow([])
    #write bad password errors
    wr.writerow(["Bad Password Errors"])
    wr.writerow(("Date", "User Name", "Error"))
    wr.writerows(bad_password_export_data)

myfile.close()