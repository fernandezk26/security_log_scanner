import os
import csv
from datetime import date
import re as regex
from itertools import zip_longest
import random
from pathlib import Path
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib, ssl
from email import encoders


#specify the full log file directory and file here
path = os.path.join('C:\\Users\\kevin.fernandez\\Documents\\sample_logs', 'netlogon.log')

def scan_security_log(filePath):
    #open the file
    with open(filePath, 'r') as f:
        log = f.readlines()

    #iterate through the log and find unknown user name errors, append to list
    unknown_user_name_errors = [] 
    for entry in log:
        if '0xC0000064' in entry:
            unknown_user_name_errors.append(entry)

    #declare lists that will be used in uknown user password table in the csv later
    uu_date_time = []
    uu_computer_names = []
    uu_error_numbers = []
    #Find and extract specific information from the list to be written to their own columns in a csv file later
    #Example: 06/01 16:03:13 [LOGON] [20004] DomainInitials: SamLogon: Network logon of Domain\ComputerName from ComputerName Returns 0xC0000064
    for entry in unknown_user_name_errors:
        uu_error_numbers.append(entry.split("Returns")[1])
        uu_error_numbers = [i.strip() for i in uu_error_numbers]   
        uu_computer_names.append(regex.search('from\ (.*?)\ Returns', entry).group(1))
        uu_date_time.append(entry.split("[")[0])

    #iterate through the log and find bad password errors, append to list
    bad_password_errors = []
    for entry in log:
        if '0xC000006A' in entry:
            bad_password_errors.append(entry)

    #declare lists that will be used in bad password table in csv later
    bp_date_time = []
    bp_user_name = []
    bp_error_numbers = []
    #Find and extract specific information from the list to be written to their own columns in a csv file later
    #Example: 06/01 16:07:31 [LOGON] [19920] DomainInitials: SamLogon: Transitive Network logon of Domain\first.lastname from  (via DC) Returns 0xC000006A
    for entry in bad_password_errors:
        bp_error_numbers.append(entry.split("Returns")[1])
        bp_error_numbers = [i.strip() for i in bp_error_numbers]   
        bp_user_name.append(regex.search('of\ (.*?)\ from', entry).group(1))
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

    #check file path to make sure there is not any files with the same name, if there is, add a random number to make the name unique
    data_directory = Path('C:\\Users\\kevin.fernandez\\Documents\\sample_logs')
    files = sorted(os.listdir(data_directory))
    for file in files:
        if file == filename:
            number = random.randint(1, 999)
            filename = f"NetLogon_flagged_errors_{str(today)}{number}.csv"

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

    #clear the log file
    with open(path, 'w') as f:
        pass
    
    #close the file
    myfile.close()
    return filename

#console log
filename = scan_security_log(filePath=path)
print(f"{filename} has been created")


#send attachment as email, using mailjet for this example. 
#You can change the username and password to your own, as well as the server if you have your own SMTP relay, or a service email account
port = 587
server = "in-v3.mailjet.com"
sender = "authenticated_email@domain.com"
recipient = "recipient@domain.com"
user = "API_KEY_HERE"
password = "SECRET_KEY_HERE"
msg = MIMEMultipart()       
message = "This email includes an attachment"
msg.attach(MIMEText(message, "plain"))
filename = "./" + filename
with open(filename, "rb") as csv_file:
    attachment = MIMEBase("application", "octet-stream")
    attachment.set_payload(csv_file.read())
encoders.encode_base64(attachment)
attachment.add_header(
    "Content-Disposition",
    f"attachment; filename= {filename}",
)
msg.attach(attachment)
SSLcontext = ssl.create_default_context()
with smtplib.SMTP(server, port) as server:
    server.starttls(context=SSLcontext)
    server.login(user, password)
    server.sendmail(sender, recipient, msg.as_string())