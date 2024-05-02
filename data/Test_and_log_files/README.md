# Step-by-step example run of the EHExtractor analyzer

The following describes an example run of the (installed) EHExtractor analyzer on a never-before-analyzed 32-bit MSVC-compiled binary. (Test binaries with corresponding reference output log files are available from the [data/Test_and_log_files](/data/Test_and_log_files) folder.)

1. Start Ghidra.
2. Import a binary in the project window using all defaults.
3. Open the imported binary.
4. Answer 'Yes' when asked to analyze the file now, or say 'No' and open Analysis/Auto Analyze yourself.
5. Choose 'standard defaults' for the analyzers to use and click 'Analyze'.
6. Wait for the analysis to complete.
7. Run Analysis/One Shot/Shared Return Calls.
8. Open Analysis/Auto Analyze.
9. Disable all analyzers (click 'Deselect all').
10. Enable EHExtractor.
11. Choose the desired location for the output log ('Log file path').
12. Leave 'Minimum log level' set to 'INFO' and 'Prefix log level' unchecked.
13. Click 'Analyze'. EHExtractor will now start.
14. EHExtractor will give a few updates in the Project window (such as starting, working, finished). The output log file path is included in the start and finish messages. These can also be seen in Ghidra's application log.
15. When finished, open the output log file to examine the results.

Some notes:
- Repeated runs of EHExtractor with the same output log file will add to that file, not overwrite it.
- EHExtractor can also be started from Analysis/One Shot, but the options cannot be changed there.

![Ghidra project window with EHExtractor finished message.](/data/Images/Project_finished.png)<br>
The Ghidra project window with an 'EHExtractor finished' message.
