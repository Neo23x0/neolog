using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO;
using System.Text.RegularExpressions;
using System.Collections;

using System.Net;
using CommandLine.Utility;
using System.Diagnostics;

namespace neolog
{
    class NeoLogger
    {

        // This object
        // private SyslogSender neolog;
        private SyslogClient.Client neolog;

        // Defaults
        private string ip = "127.0.0.1";
        private int port = 514;
        private int facility = 14;
        private int priority = 5;
        private string prefix = "NeoLogger: ";
        private string message = "Follow the white rabbit ...";
        private string file = "dummy";
        private bool debug = false;

        private string grep;                                   // Select lines matching this expression
        private string grepv;                                  // Select lines NOT matching this expression
        private bool suppressEmptyLines = true;
        private bool ignoreCase = false;
        private string searchValue;
        private string replacementValue;
        private bool onlyTail = false;
        private bool onlyNew = false;
        private bool onlyASCII = false;
        private bool filenameAsPrefix = false;
        private long maxLines = 0;
        private long sentLines = 0;

        private EventLog ev;
        private string eventlogType = "Security";

        private string dir;
        private string file_filter = "*.*";
        private bool includeSubdirectories = false;
        private string lastFileRead = "";

        private Dictionary<string, long> filePositions;

        private int readType = 1; // 1 = standard input stream, 2 = single message, 3 = file, 4 = eventlog, 5 = watcher 

        // Counter Vars
        private long filePos = 0;
        private int eventlogPos = 0;

        // NEOLOGGER CLASS
        public NeoLogger (string[] args) {

            // Parse the Command Line Arguments
            this.parseCommandLine(args);
        
            // Creating the syslogsender object
            this.neolog = new SyslogClient.Client();

            // Setting Parameters
            //neolog.RemoteAddress = ip;
            //neolog.RemotePort = port;
            //neolog.PriorityNumber = priority;
            //neolog.FacilityName = facility;
            //neolog.UseUTF8 = true;
            neolog.SysLogServerIp = ip;
            neolog.Port = port;

            // File Positions Dictionary
            filePositions = new Dictionary<string, long>();

// INPUT ######################################################################

            // Input Stream
            if (readType == 1)
            {
                string line;
                // Read input stream lines
                while ((line = Console.ReadLine()) != null)
                {
                    verifiedSend(line);
                }
            }

            // Single Message
            if (readType == 2)
            {
                send(message);
            }

            // File Input
            if (readType == 3)
            {
                // Read only tail lines ----------------------------------------------------
                if (onlyTail)
                {

                    // Open the file
                    StreamReader filestream = null;
                    filestream = new StreamReader(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
                    // Got to the End of the file
                    filestream.BaseStream.Seek(0, SeekOrigin.End);
                    // Save position
                    filePositions.Add(file, filestream.BaseStream.Position);
                    filestream.Close();

                    // Create a watcher
                    FileSystemWatcher watcher = new FileSystemWatcher();
                    watcher.Path = Path.GetDirectoryName(file);
                    watcher.Filter = Path.GetFileName(file);
                    watcher.NotifyFilter = NotifyFilters.LastWrite;

                    // Add event handlers.	 
                    watcher.Changed += new FileSystemEventHandler(OnChangedFile);
                    // Start watching
                    watcher.EnableRaisingEvents = true;
                    // watcher.WaitForChanged(WatcherChangeTypes.Changed);

                    // Print hint and wait
                    printHint("Stop sending by pressing 'q'");

                }
                // Read only new lines --------------------------------------------------
                else if (onlyNew)
                {

                    // Generate file name
                    string statFile = Path.GetFileName(file) + ".stat";

                    // If stat file exists and contains a last position
                    long savedPos = getOldFilePosFromStat(statFile);
                    // Check if file has been deleted or shrinked in the meantime
                    bool isNewFile = checkFileNew(savedPos);

                    long lastPos = 0;
                    if (  savedPos > 0 && ! isNewFile ) {
                        lastPos = sendFile(this.file, savedPos);
                    }
                    else
                    {
                        lastPos = sendFile(this.file, 0);
                    }

                    // Save the last file pointer position
                    setFilePosToStat(lastPos, statFile);

                }

                // Just read the file and then exit
                else
                {
                    // Send the whole content
                    sendFile(this.file, 0);

                }
            }

            // Eventlog -------------------------------------------------------
            if (readType == 4)
            {
                try {
                    
                    // Open Eventlog
                    ev = new EventLog(eventlogType, System.Environment.MachineName);
                    int LastLogToShow = ev.Entries.Count;
                    if (LastLogToShow <= 0 && debug && !onlyTail)
                        Console.WriteLine("No Event Logs in the Log :" + eventlogType);

                    if (onlyTail)
                    {
                        // Set pointer pos to current size
                        eventlogPos = ev.Entries.Count;

                        ev.EntryWritten += new EntryWrittenEventHandler(OnEventlogChange);
                        ev.EnableRaisingEvents = true;

                        printHint("Stop sending by pressing 'q'");
                    }
                    else if (onlyNew)
                    {
                        // Generate file name
                        string statFile = eventlogType + ".stat";

                        // If file exists
                        if (File.Exists(statFile))
                        {

                            int oldIndex = getOldEventlogPosFromStat(statFile);
                            print("Stat file found. Event Record Id " + oldIndex + " read");
                            // If Eventlog is empty
                            if (ev.Entries.Count < 1)
                            {
                                print("Wanring: Eventlog is empty! Deleting stat file.");
                                File.Delete(statFile);
                            } else {
                                if (oldIndex < ev.Entries[ev.Entries.Count - 1].Index)
                                {
                                    long lastIndex = sendEventlogFromIndex(oldIndex);
                                    File.WriteAllText(statFile, lastIndex.ToString());
                                    if (lastIndex == 0)
                                    {
                                        send("NeoLogger Wanring - Windows Eventlog rotates to fast! Try increasing the eventlog size");
                                    }
                                }
                            }
                        }
                        else
                        {
                            print("No stat file for this Eventlog found. File will be created. Next time NeoLogger is invoked, only new entries will be sent.");
                            File.WriteAllText(statFile, ev.Entries[ev.Entries.Count-1].Index.ToString());
                        }
                    }
                    else
                    {
                        sendEventlog(0);
                    }
                    ev.Close();
                }
                catch (Exception ex)
                {
                    showErrorAndExit("Eventlog with name " + eventlogType + " not found or not accessible. " + ex.ToString());
                }


            }

            // Directory Watcher ----------------------------------------------
            if (readType == 5)
            {
                // Create a watcher
                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = dir;
                watcher.Filter = file_filter;
                if (includeSubdirectories)
                {
                    watcher.IncludeSubdirectories = true;
                }
                watcher.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;

                // Add event handlers.	 
                watcher.Changed += new FileSystemEventHandler(OnWatcherChangedFile);
                watcher.Created += new FileSystemEventHandler(OnWatcherChangedFile);
                watcher.Deleted += new FileSystemEventHandler(OnWatcherChangedFile);
                watcher.Renamed += new RenamedEventHandler(OnWatcherRenamed);

                // Start watching
                watcher.EnableRaisingEvents = true;
                // watcher.WaitForChanged(WatcherChangeTypes.Changed);

                // Print hint and wait
                printHint("Stop sending by pressing 'q'");

            }

            // Read Directory -------------------------------------------------
            if (readType == 6)
            {
                if (onlyTail)
                {
                    // Walk the directory and save the last positions of the the filesto the dictionary
                    DirectoryInfo directory = new DirectoryInfo(dir);
                    WalkDirectoryTree(directory);

                    // Create a watcher
                    FileSystemWatcher watcher = new FileSystemWatcher();
                    watcher.Path = dir;
                    watcher.Filter = file_filter;
                    if (includeSubdirectories)
                    {
                        watcher.IncludeSubdirectories = true;
                    }
                    watcher.NotifyFilter = NotifyFilters.LastWrite;

                    // Add event handlers.	 
                    watcher.Changed += new FileSystemEventHandler(OnChangedFile);
                    watcher.Created += new FileSystemEventHandler(OnChangedFile);

                    // Start watching
                    watcher.EnableRaisingEvents = true;
                    // watcher.WaitForChanged(WatcherChangeTypes.Changed);

                    // Print hint and wait
                    printHint("Stop sending by pressing 'q'");
                }
                // Send all files content
                else
                {
                    // Walk the directory and send the file contents
                    DirectoryInfo directory = new DirectoryInfo(dir);
                    WalkDirectoryTree(directory);
                }

            }

            // Close Socket
            neolog.Close();

        }


// SEND #####################################################################

        // Verified send
        private void verifiedSend(string line)
        {
            // GREP checks (positive filter)
            if (grep != null)
            {
                if (! regexCheck(line, grep, false))
                {
                    return;
                }
            }
            // GREPV checks (negative filter)
            if (grepv != null)
            {
                if (regexCheck(line, grepv, false))
                {
                    return;
                }
            }

            // Check if empty line
            if (suppressEmptyLines)
            {
                if (regexCheck(line, @"^[\s\t]*$", false))
                {
                    return;
                }
            }

            // Replacements
            if ( searchValue != null && replacementValue != null ) {
                line = regReplace(searchValue, replacementValue, line);
            }

            // ASCII Only
            if (onlyASCII)
            {
                line = regReplace(@"[^\x20-\x7E\x0A\x0D\x09]", "", line);
            }

            // Clean Line
            line = regReplace(@"[\n\r]+"," ", line);

            // Else ... just send the crap
            send(line);

            // DoS control
            if (maxLines > 0 && !onlyTail)
            {
                sentLines++;
                if (sentLines >= maxLines)
                {
                    send("NeoLogger Max Line Limit reached");
                    showMessageAndExit("Max Lines reached - terminating.");
                }
            }

        }

        // Send
        private void send(string line)
        {
            // Prefix changes
            if (filenameAsPrefix)
            {
                prefix = lastFileRead + " : ";
            }

            // Debugging
            if (debug) Console.WriteLine("Sending to " + ip + " Port " + port + " : " + prefix + line);
            
            // Construct message
            string message = prefix + line;
            neolog.Send(new SyslogClient.Message(this.facility, this.priority, message));
        }

        // Send a File Content starting at position x
        long sendFile(string filename, long startPos)
        {
            try
            {
                // Open the file
                StreamReader filestream = null;
                filestream = new StreamReader(new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite), System.Text.Encoding.Default);

                // False Positive - Invoked by accident
                if (startPos == filestream.BaseStream.Length)
                {
                    //print("File has no new bytes - returning");
                    return startPos;
                }

                // File has been shrinked or rotated - send the whole file anew
                if (startPos > filestream.BaseStream.Length)
                {
                    verifiedSend("File " + filename + " shrinked or rotated - sending file anew ...");
                    startPos = 0;
                }

                // Set the las file read for the use in "filename as prefix"
                this.lastFileRead = filename;

                string line = "";
                print("Sending file - starting at " + startPos);
                filestream.BaseStream.Seek(startPos, SeekOrigin.Begin);

                // Read everything new
                while ((line = filestream.ReadLine()) != null)
                {
                    verifiedSend(line);
                }
                
                // Set new position
                if (filePositions.ContainsKey(filename))
                {
                    filePositions[filename] = filestream.BaseStream.Position;
                }
                else
                {
                    filePositions.Add(filename, filestream.BaseStream.Position);
                }

                // Close the stream
                filestream.Close();
                
                return filePositions[filename];
            }
            catch (IOException ex)
            {
                showErrorAndExit("IO Exception while reading " + file + " - " + ex.ToString());
            }
            return 0;

        }

        // Send Eventlog
        private long sendEventlogFromIndex(long startIndex)
        {

            long lastIndex = 0;
            bool readActive = false; // Activated when last index found
            try
            {             
                // Send entries from startPos
                int i;
                for ( i = 0 ; i < ev.Entries.Count ; i++ ) 
                {
                    if ( readActive ) {
                        EventLogEntry CurrentEntry = ev.Entries[i];
                        lastIndex = CurrentEntry.Index;
                        // print("Index: "+CurrentEntry.Index.ToString());
                        verifiedSend(CurrentEntry.TimeGenerated + "\t" + CurrentEntry.InstanceId + "\t" + CurrentEntry.Source + "\t" + CurrentEntry.Message);
                    }
                    if (ev.Entries[i].Index == startIndex && !readActive)
                    {
                        readActive = true;
                    }
                }
                eventlogPos = i;
            }
            catch (Exception ex)
            {
                showErrorAndExit("Eventlog with name " + eventlogType + " not found or not accessible. " + ex.ToString());
            }

            return lastIndex;
        }

        // Send Eventlog
        private void sendEventlog(int startPos)
        {

            try
            {
                // Send entries from startPos
                int i;
                for (i = startPos; i < ev.Entries.Count; i++)
                {
                    EventLogEntry CurrentEntry = ev.Entries[i];
                    verifiedSend(CurrentEntry.TimeGenerated + "\t" + CurrentEntry.InstanceId + "\t" + CurrentEntry.Source + "\t" + CurrentEntry.Message);
                }
                this.eventlogPos = i;
            }
            catch (Exception ex)
            {
                showErrorAndExit("Eventlog with name " + eventlogType + " not found or not accessible. " + ex.ToString());
            }

        }

// FILE #######################################################################

        // Get old filepos from stats file
        private long getOldFilePosFromStat(string statFile) {

            // Las position default
            long oldPos = 0;

            if (File.Exists(statFile))
            {
                try
                {
                    oldPos = long.Parse(File.ReadAllText(statFile));
                }
                catch (Exception e)
                {
                    showErrorAndExit("Error reading stat file : " + e.ToString());
                }
            }
            return oldPos;
        }

        // Get old filepos from stats file
        private int getOldEventlogPosFromStat(string statFile)
        {

            // Las position default
            int oldPos = 0;

            if (File.Exists(statFile))
            {
                try
                {
                    oldPos = Convert.ToInt32(File.ReadAllText(statFile));
                }
                catch (Exception e)
                {
                    showErrorAndExit("Error reading stat file : " + e.ToString());
                }
            }
            return oldPos;
        }

        // Set the last read position to the stat file
        private void setFilePosToStat(long lastPos, string statFile)
        {
            // Now write the new filePos to the Stat file
            try
            {
                File.WriteAllText(statFile, lastPos.ToString());
            }
            catch (Exception e)
            {
                showErrorAndExit("Cant open stat file for writing : " + e.ToString());
            }
        }

        // Send a File Content starting at position x
        bool checkFileNew(long checkPos)
        {

            long endPos = 0;

            try
            {
                // Open the file
                StreamReader filestream = null;
                filestream = new StreamReader(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite), System.Text.Encoding.Default);
                endPos = filestream.BaseStream.Length;
                filestream.Close();

            }
            catch (IOException ex)
            {
                showErrorAndExit("IO Exception while reading " + file + " - " + ex.ToString());
            }

            // if new endpos is smaller than the last endpos
            if (endPos < checkPos)
            {
                // new File
                print("File is smaller than the last time seen - starting to read from the beginning again...");
                return true;
            }
            else
            {
                return false;
            }

        }

        // On File Changes
        private void OnChangedFile(object sender, FileSystemEventArgs e)
        {
            long lastPos;
            // Known file
            if ( filePositions.ContainsKey(e.FullPath) ) {
                filePositions.TryGetValue(e.FullPath, out lastPos);
                sendFile(e.FullPath, lastPos);
            }
            // Newly Created file
            else
            {
                sendFile(e.FullPath, 0);
            }
        }

        // Watcher noticed changed file
        private void OnWatcherChangedFile(object sender, FileSystemEventArgs e)
        {
            if (! Directory.Exists(e.FullPath))
            {
                WatcherChangeTypes wct = e.ChangeType;
                string watcher_message = "File " + e.FullPath + " - " + wct.ToString();
                verifiedSend(watcher_message);
            }
        }

        // Watcher noticed file rename
        private void OnWatcherRenamed(object sender, RenamedEventArgs e)
        {
            WatcherChangeTypes wct = e.ChangeType;
            string watcher_message = "File " + e.OldFullPath + " " + e.FullPath + " - " + wct.ToString();
            verifiedSend(watcher_message);
        }

        // Watcher error
        private void OnWatcherError(object sender, FileSystemEventArgs e)
        {
            showErrorAndExit("FileSystemWatcher Error: "+e.ToString());
        }

        // Walk Directory Tree
        private void WalkDirectoryTree(System.IO.DirectoryInfo root)
        {
            System.IO.FileInfo[] files = null;
            System.IO.DirectoryInfo[] subDirs = null;

            // First, process all the files directly under this folder
            try
            {
                files = root.GetFiles("*.*");
            }
            catch (UnauthorizedAccessException e)
            {
                showErrorAndExit(e.Message);
            }

            catch (System.IO.DirectoryNotFoundException e)
            {
                showErrorAndExit(e.Message);
            }

            if (files != null)
            {
                foreach (System.IO.FileInfo fi in files)
                {
                    // What to do with the file
                    // if "tail" function - only check where the file ends
                    if (this.onlyTail)
                    {
                        if (wildcardCheck(fi.Name, file_filter))
                        {
                            this.saveFilePosition(fi.FullName);
                        }
                    }
                    // send the file
                    else
                    {
                        print("Attrib: " + fi.Attributes);
                        if (wildcardCheck(fi.Name, file_filter))
                        {
                            this.sendFile(fi.FullName, 0);
                        }
                    }
                }

                // Now find all the subdirectories under this directory.
                subDirs = root.GetDirectories();

                foreach (System.IO.DirectoryInfo dirInfo in subDirs)
                {
                    // Resursive call for each subdirectory.
                    WalkDirectoryTree(dirInfo);
                }
            }
        }

        // Save the last position of the given file
        private void saveFilePosition(string filename)
        {
            try
            {
                // Open the file
                StreamReader filestream = null;
                filestream = new StreamReader(new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite), System.Text.Encoding.Default);
                long end = filestream.BaseStream.Length;
                filestream.Close();

                // Save to dirctionary
                filePositions[filename] = end;

            }
            catch (IOException ex)
            {
                showErrorAndExit("IO Exception while reading " + file + " - " + ex.ToString());
            }
        }

// EVENTLOG ###################################################################

        // On Written Eventlog
        private void OnEventlogChange(object source, EntryWrittenEventArgs e)
        {
            sendEventlog(eventlogPos);
        }

        // Get Event with Index
        private EventLogEntry getEventWithIndex(long index)
        {
            for (int i = 0; i < ev.Entries.Count; i++)
            {
                if (ev.Entries[i].Index == index)
                {
                    return ev.Entries[i];
                }
            }
            return ev.Entries[0];
        }

// PARAMETERS #################################################################

        // Parses the Command Line Parameters
        void parseCommandLine(string[] args)
        {

            // Command line parsing
            Arguments CommandLine = new Arguments(args);

            // No arguments or "h" or "?" shows help
            if (args.Length < 1 || CommandLine["h"] != null || CommandLine["?"] != null ) 
            {
                showHelpAndExit();
            }

            // If unknown parameter
            foreach (string entry in CommandLine)
            {
                if (!regexCheck(entry, @"^([tplfmdrngiae]|prefix|et|gv|rv|sv|tail|max|dir|ff|sub|watch|fn)$", false))
                {
                    showErrorAndExit("Parameter \"" + entry + "\" is unknown. Check the available parameters with -h.");
                }
            }

            // Temp vars
            string target = this.ip;

            // Command Line Arguments
            // Read & Write Optiones
            // default readType is 1
            // Single Line
            if (CommandLine["m"] != null)
            {
                this.readType = 2;
                this.message = CommandLine["m"];
            }
            // Read from File
            if (CommandLine["r"] != null)
            {
                this.readType = 3;
                this.setFile(CommandLine["r"]);
            }
            // Read from local Eventlog
            if (CommandLine["et"] != null)
            {
                this.readType = 4;
                this.setEventlogType(CommandLine["et"]);
            }
            // Watcher
            if (CommandLine["dir"] != null && CommandLine["watch"] != null )
            {
                this.readType = 5;
                this.setWatchDir(CommandLine["dir"]);
            }
            // Read from directory
            if (CommandLine["dir"] != null && CommandLine["watch"] == null)
            {
                this.readType = 6;
                this.setWatchDir(CommandLine["dir"]);
            }

            // If another source AND the Eventlog Source is given
            // then set the Eventlog as target
            // TODO

            // Other Options
            if (CommandLine["t"] != null)
            {
                this.setTarget(CommandLine["t"]);
            }
            if (CommandLine["p"] != null)
            {
                this.setPort(CommandLine["p"]);
            }
            if (CommandLine["l"] != null)
            {
                this.setPriority(CommandLine["l"]);
            }
            if (CommandLine["f"] != null)
            {
                if ( ! this.setFacility(CommandLine["f"]))
                {
                    showErrorAndExit("Facility \"" + CommandLine["f"] + "\" unknown. Please check spelling.\nAvailable values are: kernel, user, mail, daemon, auth, syslog, lpr, news, \nuucp, cron, security, ftp, ntp, audit, alert, clock, local0, local1, local2, \nlocal3, local4, local5, local6, local7.\n\nSee RCF3164 for details.");
                }
            }
            if (CommandLine["prefix"] != null)
            {
                this.prefix = CommandLine["prefix"];
            }
            if (CommandLine["d"] != null)
            {
                this.debug = true;
            }
            if (CommandLine["tail"] != null)
            {
                this.onlyTail = true;
            }
            if (CommandLine["n"] != null)
            {
                this.onlyNew = true;
            }
            if (CommandLine["g"] != null)
            {
                if (debug) Console.WriteLine("Setting grep to " + CommandLine["g"]);
                this.grep = CommandLine["g"];
            }
            if (CommandLine["gv"] != null)
            {
                this.grepv = CommandLine["gv"];
            }
            if (CommandLine["e"] != null)
            {
                this.suppressEmptyLines = false;
            }
            if (CommandLine["i"] != null)
            {
                this.ignoreCase = true;
            }
            if (CommandLine["a"] != null)
            {
                this.onlyASCII = true;
            }
            if (CommandLine["sv"] != null) {
                this.searchValue = CommandLine["sv"];
            }
            if (CommandLine["rv"] != null) {
                this.replacementValue = CommandLine["rv"];
            }
            if (CommandLine["max"] != null)
            {
                this.setMaxLines(CommandLine["max"]);
            }
            if (CommandLine["sub"] != null)
            {
                if (this.dir == null)
                {
                    showErrorAndExit("Subdirectories options makes no sense without a given directory.");
                }
                this.includeSubdirectories = true;
            }
            if (CommandLine["ff"] != null)
            {
                this.file_filter = CommandLine["ff"];
            }
            if (CommandLine["fn"] != null)
            {
                this.filenameAsPrefix = true;
            }

            // Bad combinations
            if ((searchValue != null && replacementValue == null) || (searchValue == null && replacementValue != null))
            {
                showErrorAndExit("If search value is used reaplacment value has to be set and vise versa.");
            }
            if (this.onlyTail && this.onlyNew)
            {
                showErrorAndExit("The option \"-tail\" (realtime watch) cannot be combined with \"-n\" (show new lines of a file)");
            }
            if (this.onlyNew && this.dir != null)
            {
                showErrorAndExit("The directory option cannot be combined with the \"-n\" option yet. Perhaps you want to try to combine it with the \"-tail\" or \"-watch\" option.");
            }

        }

// SET AND GET ################################################################

        public void setTarget(string target)
        {
            // Check if target is a string or ip address
            if (regexCheck(target, @"^\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$", false))  
            {
                //Console.WriteLine(target + " is IP");
                this.ip = target;
            }
            else
            {
                //Console.WriteLine(target + " is DNS name");
                this.ip = getIP(target);
            }

        }

        public void setPort(string port)
        {
            if ( regexCheck( port, @"^[0-9]+$", false ) ) {
                if ( Convert.ToInt32(port) < 65535 ) {
                    this.port = Convert.ToInt32(port);
                } else {
                   showErrorAndExit("Port number too high!");
                }
            } else {
                showErrorAndExit("Port number is not numeric");
            }
        }

        public void setPriority(string priority)
        {
            if ( regexCheck( priority, @"^[0-9]+$", false ) ) {
                if ( Convert.ToInt32(priority) < 8 ) {
                    this.priority = Convert.ToInt32(priority);
                } else {
                   showErrorAndExit("level number too high! 1-7 is valid.");
                }
            } else {
                showErrorAndExit("Level is not numeric. Available values are: 0 = Emergency, 1 = Alert, 2 = Critical, 3 = Error, 4 = Warning, 5 = Notice, 6 = Informational, 7 = Debug\n\nSee RCF3164 for details.");
            }
        }

        public void setWatchDir(string dir)
        {
            string dir_temp = dir;
            if (Directory.Exists(dir_temp))
            {
                this.dir = dir;
            }
            else
            {
                showErrorAndExit("Directory " + dir_temp + " not found.");
            }
        }

        public bool setFacility(string facility)
        {
            Array obj = Enum.GetValues(typeof(SyslogClient.Facility));
            int i = 0;
            foreach ( SyslogClient.Facility fac in obj ) {
                if ( regexCheck(facility, @"^"+fac+"$", true) ) {
                    this.facility = i;
                    return true;
                }
                i++;
            }

            return false;
        }

        public void setMaxLines(string maxLines)
        {
            if (regexCheck(maxLines, @"^[0-9]{1,9}$", false))
            {
                this.maxLines = long.Parse(maxLines);
            }
            else
            {
                showErrorAndExit("Value for max lines to high or invalid.");
            }
        }

        public void setFile(string file)
        {
            // If not absolute path given
            if ( ! regexCheck(file, @"[\\/]+", false ) ) {
                file = Directory.GetCurrentDirectory()+"\\"+file;
                if ( debug ) Console.WriteLine("Setting file to "+file);
            }

            if (File.Exists(file))
            {
                this.file = file;
            }
            else
            {
                showErrorAndExit("File " + file + " does not exist");
            }
        }

        public void setEventlogType(string et)
        {
            this.eventlogType = et;
        }

// REGEX ######################################################################

        // Regex Check - To simplify the checking
        private bool regexCheck(string value, string expression, bool insensitive )
        {
            Regex rgx;
            if ( ignoreCase || insensitive )
            {
                rgx = new Regex(expression, RegexOptions.IgnoreCase);
            }
            else
            {
                rgx = new Regex(expression);
            }

            MatchCollection matches = rgx.Matches(value);
            if (matches.Count > 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        // Regex Check - To simplify the checking
        private bool wildcardCheck(string value, string expression)
        {
            string wildcard = expression;
            wildcard = wildcard.Replace(".", "\\.");
            wildcard = wildcard.Replace("*", ".*");
            
            Regex rgx;
            if (ignoreCase)
            {
                rgx = new Regex(wildcard, RegexOptions.IgnoreCase);
            }
            else
            {
                rgx = new Regex(wildcard);
            }

            MatchCollection matches = rgx.Matches(value);
            if (matches.Count > 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        // Regex Replacement
        private string regReplace (string searchValue, string replacementValue, string line) {
            Regex rgx = new Regex(searchValue);
            string result = rgx.Replace(line, replacementValue);
            return result;
        }

// SPECIAL FUNCTIONS ##########################################################

        private void print(string value)
        {
            if ( debug ) Console.WriteLine(value);
        }

        private void printHint(string value)
        {
            Console.WriteLine(value);
            while (Console.ReadKey().KeyChar != 'q') ;
        }

        // Resolves a DNS name
        private string getIP(string hostname)
        {
            string returnvalue = "";
            IPHostEntry host;
            try
            {
                host = Dns.GetHostEntry(hostname);
                // Console.WriteLine("Resolving " + hostname + " to " + host.AddressList.First().ToString());
                returnvalue = host.AddressList.First().ToString();
            }
            catch (Exception ex)
            {
                showErrorAndExit("Cant lookup DNS name " + hostname + " : " + ex.ToString());
            }
            return returnvalue;
        }

// EXIT FUNCTIONS #############################################################

        // Help and Exit
        public void showHelpAndExit()
        {
            Console.WriteLine("=====================================================");
            Console.WriteLine("NeoLogger v0.6.2");
            Console.WriteLine("Windows Syslog Command Line Logger");
            Console.WriteLine("Florian Roth, 2012");
            Console.WriteLine("=====================================================");
            Console.WriteLine("");
            Console.WriteLine("Input Options:");
            Console.WriteLine("  1.   Standard input stream (default if nothing else is defined)");
            Console.WriteLine("  2.   File input set with the \"-r\" parameter");
            Console.WriteLine("  3.   Single line set with the \"-m\" parameter");
            Console.WriteLine("  4.   Windows Eventlog Source using the \"-et\" parameter");
            Console.WriteLine("");
            Console.WriteLine("Standard Parameters:");
            Console.WriteLine("  -t      Target (ip or dns name) default: 127.0.0.1");
            Console.WriteLine("  -p      Port (target port) default: 514");
            Console.WriteLine("  -l      Level (1-7, 1=kernel ... 7=debug) default: 5=notice");
            Console.WriteLine("  -f      Facility (local1,local2...) default: local4");
            Console.WriteLine("  -d      Debug switch");
            Console.WriteLine("  -m      Message default: \"Follow the white rabbit\"");
            Console.WriteLine("  -prefix default: \"NeoLogger: \"");
            Console.WriteLine("");
            Console.WriteLine("Special Parameters:");
            Console.WriteLine("  -r      Filename i.e. \"C:\\Program Files\\Trendmicro\\updinfo.ini\"");
            Console.WriteLine("  -dir    Directory to observe i.e. \"D:\\FileShare\\\"");
            Console.WriteLine("  -et     Read Windows Eventlog i.e. \"Application\" (Security needs \'elevate ...\')");
            Console.WriteLine("");
            Console.WriteLine("Special Functions:");
            Console.WriteLine("  -sub    Include subdirectories");
            Console.WriteLine("  -ff     File Filter to apply i.e. \"*.log\", default: \"*.*\"");
            Console.WriteLine("  -n      Read new entries only - applies to single files and Eventlog as input");
            Console.WriteLine("  -tail   Read new entrys only (like tail -f); applies to \"-r\" and \"-et\"");
            Console.WriteLine("  -watch  Observe file system actions in the given directory");
            Console.WriteLine("  -fn     Set the file name as prefix. Often used with \"-dir\"");
            Console.WriteLine("");
            Console.WriteLine("Filter/Replace Features:");
            Console.WriteLine("  -g      Regex/String to select lines to be send i.e. \"sshd\"");
            Console.WriteLine("  -gv     Regex/String to filter lines from output i.e. \"courier:\"");
            Console.WriteLine("  -i      Ignore case of string set by -g or -gv ");
            Console.WriteLine("  -a      Readable ASCII characters only (including space and tab)");
            Console.WriteLine("  -e      Dont supress empty lines");
            Console.WriteLine("  -sv     Search value i.e. \"[\\s]+\" (multiple spaces)");
            Console.WriteLine("  -rv     Replacement value i.e. \" \" (single space)");
            Console.WriteLine("  -max x  DoS control - send a maximum of x messages per run (does not apply to \"-tail\")");
            Environment.Exit(1);
        }

        // Error and Exit
        public void showErrorAndExit(string error)
        {
            Console.WriteLine("Error: " + error);
            Environment.Exit(2);
        }

        // Message and Exit
        public void showMessageAndExit(string message)
        {
            Console.WriteLine("Notice: " + message);
            Environment.Exit(1);
        }

    }
}
