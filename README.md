# security_log_scanner
This script iterates through a Windows Domain Controller NetLogon log file, finds specific entries with specific errors including bad password errors, unknknown user errors
and lock out errors, extracts only the necessary info from those entries, then exports the entries to a csv, under their own respective columns. 

Will include email functionality in the future. 
