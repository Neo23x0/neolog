NeoLog v0.6.2
=====================================================
# Windows Syslog Command Line Logger
# Florian Roth, 2012

### Input Options
  1.   Standard input stream (default if nothing else is defined)
  2.   File input set with the "-r" parameter
  3.   Single line set with the "-m" parameter
  4.   Windows Eventlog Source using the "-et" parameter

### Standard Parameters

-t      Target (ip or dns name) default: 127.0.0.1

-p      Port (target port) default: 514

-l      Level (1-7, 1=kernel ... 7=debug) default: 5=notice

-f      Facility (local1,local2...) default: local4

-d      Debug switch

-m      Message default: "Follow the white rabbit"

-prefix default: "NeoLogger: "

### Special Parameters

-r      Filename i.e. "C:\Program Files\Trendmicro\updinfo.ini"

-dir    Directory to observe i.e. "D:\FileShare\"

-et     Read Windows Eventlog i.e. "Application" (Security needs 'elevate ...')

### Special Functions

-sub    Include subdirectories

-ff     File Filter to apply i.e. "*.log", default: "*.*"

-n      Read new entries only - applies to single files and Eventlog as input

-tail   Read new entrys only (like tail -f); applies to "-r" and "-et"

-watch  Observe file system actions in the given directory

-fn     Set the file name as prefix. Often used with "-dir"

### Filter/Replace Features

-g      Regex/String to select lines to be send i.e. "sshd"

-gv     Regex/String to filter lines from output i.e. "courier:"

-i      Ignore case of string set by -g or -gv

-a      Readable ASCII characters only (including space and tab)

-e      Dont supress empty lines

-sv     Search value i.e. "[\s]+" (multiple spaces)

-rv     Replacement value i.e. " " (single space)

-max x  DoS control - send a maximum of x messages per run (does not apply to "-tail")
  
### Special function descriptions

-n    Read new entries only

Every time neologger is startet with the "-n" option the given file or eventlog is read to the end and a stat-file is created containing the last position of the file or eventlog.  When NeoLogger is invoked another time, it reads the stat file and starts sending from the position it ended the last time. 
If the file has been shrinked in the meanwhile, neologger considers the file as new and starts from the beginning again. 
In case of the Eventlog, NeoLogger does not check the count of the entries as they are rotated frequently. It searches for the so called "Event Record ID" of the last entry detected and sends all events from this entry. It takes some time to search for the entry by record id but it is more reliable.

-dir  Directory to observe i.e. "D:\FileShare\"

Combined with "-tail" it watches for changes on files in a given directory and sends the new lines in these files. Combined with "-watch" it watches for changes to files 
and sends a message about the change that happend to a file.

Example for "-tail":
Sending to 127.0.0.1 Port 514 : C:\logfiles\test.log : First new line in log file
Sending to 127.0.0.1 Port 514 : C:\logfiles\test.log : Second new line in log file
Sending to 127.0.0.1 Port 514 : C:\logfiles\subdirectory\another.log : Another line in a log file

Example for "-watch":
Sending to 127.0.0.1 Port 514 : NeoLogger: File C:\logfiles\windows.log - Changed
Sending to 127.0.0.1 Port 514 : NeoLogger: File C:\logfiles\super.log - Deleted
Sending to 127.0.0.1 Port 514 : NeoLogger: File C:\logfiles\readme.txt C:\logfiles\readme-new.txt - Renamed

### Known Issues

* Security Eventlog

In Windows Vista/7/2008 the "Security" eventlog is only accessible to users with elevated rights. In former versions I packed the utitlity "elavate" and "elavate64" with the neologger package. It is still available at http://code.kliu.org/misc/elevate/ for download. Thanks to Kai Liu for contribution.

* Parameter Combinations

I have not yet catched all conflicting parameter combinations. Please send me the command line if a combinations causes the program to exits unexpectedly.

* Directory Observation and Binary Files

Neologger is not yet checking if a file is ASCII text so it is your obligation to check the directory content and adapt the filter setting. If you set "-ff '*.log'" and one of these .log-files contains binary content, it is send as it is - causing neologger to fail and perhaps the syslog receiver as well. ;)

### Support

Please tell me if "neologger" did not run in your environment. 
I tested it on Windows 7 x86 but noticed problems with the .NET 3.5 version on Windows 2008 with .NET 4. I tried to make it usable on both Framework versions but am not sure if it worked. 

Tested on:
- Windows 7 x86 (DE) and .NET 4.0
- Windows XP (EN) and .NET 3.5
- Windows 2003 x86 (EN) and .NET 4.0
- Windows 2008 R2 x64 (EN) and .NET 4.0
  
### Requirements

.NET Framework 3.5 (Client Profile) OR .NET Framework 4.0

### License

Apache License V2.0
  
### Examples
  
Transmit TrendMicro Office Server Signature Pattern information 
neolog.exe -t syslog.intranet.local -r "C:\Programme\TrendMicro\updinfo.ini" -g "pattern"

Transmit currently logged in users
WMIC COMPUTERSYSTEM get username | neolog.exe -t syslog.intranet.local -gv UserName

Transmit the values from the "Run" key 
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | neolog.exe -t syslog.intranet.local -gv HKEY -sv "[\s]+" -rv " "

### New since version 0.3

Transmit all new entries to the Application Eventlog (Note: Windows Vista, 7 and 2008 require elevated rights to access the "Security" Eventlog. Use the tool "elevate" which is packed with NeoLogger)
neolog.exe -t syslog.intranet.local -tail -et "Application"

Transmit all entries of the Windows Firewall Log (Access rights have to be set!)
neolog.exe -t syslog.intranet.local -tail -r C:\Windows\system32\LogFiles\Firewall\pfirewall.log

### New since version 0.4

First program run: No events are transmitted. The last event - references by its event record id - is stored.
Second program run: Only new events since the last run are transmitted.

neolog.exe -t 10.0.0.1 -n -et Application

First program run: The complete file is transmitted. The end position of the file is stored. 
Zweiter Aufruf: Only new lines since the last run are transmitted.

neolog.exe -t 10.0.0.1 -n -r logfile.txt

### New since version 0.5

Since version 0.5 it is possible to watch a directory (optional: with subdirectories) for changes and send the new lines of the changed files. 
The next example watches the directory (-dir) and subdirectories (-sub) for changes (-tail) in the files ending with ".log" (-ff). The file name in which the change occured is set to be the prefix of the log line (-fn).

neolog.exe -d -t 10.0.0.1 -dir "C:\logfiles" -sub -ff "*.log" -fn -tail

Neolog can observe the file system now. It watches over a directory and sens messages when files have been changes, created, deletet or renamed. Unfortunately due to limitations of the Windows Operating System it is not pssible to evaluate the user that did the changes.

nelog.exe -d -t 10.0.0.1 -dir "C:\fileshare" -watch

==== History

0.6.2 - Bugfix Verson: Facility and Level Bugfix, Removed \n at end of line

0.6 - Complete rewrite of the syslog client class - Formerly imported from (Kiwi Syslog Client DLL: KLOG_NET.dll) - now integrated in neologger

0.5 - Observation of multiple logfile within a directory and subdirectories, File System Observation (when changed what file)

0.4.1 - Bugfix Version - Changed the app.conf to make NeoLogger run on .NET 3.5 as well as 4.0 (Client Profile)

0.4 - "New Lines Only" function also for Eventlog, Max Lines function for unwanted DoS protection

0.3.4 - "Read new Lines only" and "Tail" function with new parameters.
