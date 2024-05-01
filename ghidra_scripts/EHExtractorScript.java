//This script extracts x86 MSVC exception handling information from binaries and writes it to a log file and the console.
//@author Remco Slijkhuis
//@category C++
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;

import java.nio.file.Paths;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import ehextractor.EHExtractor;
import ehextractor.Logging;
import ehextractor.ProgramValidator;
import ehextractor.SharedReturnCalls;
import loggingbridge.GhidraScriptHandler;

/**
 * Ghidra script to extract exception handling information from executables compiled with MSVC and targeted at 32-bit x86 architectures.
 * Output is logged to both a file and to the Ghidra console.
 */
public class EHExtractorScript extends GhidraScript {
	
	// The minimum log level. Level.INFO is the most useful one for everyday use.
	final Level LOG_LEVEL = Level.INFO;
	
	// Path to the output log file.
	final String LOG_FILE_PATH = Paths.get(System.getProperty("user.home"), "Documents", "ehextractor.log").toString();

	// Whether or not to prefix output lines with log levels.
	final boolean PREFIX_LOG_LEVEL = false;

	Logger logger = null;
	FileHandler fh = null;
		
    public void run() throws Exception {
    	
		// Set up a proper logger first. Exit when there are problems doing so.
    	// Note that the logger will by default log to a file but when we're running as a script,
    	// output to the console is very convenient. So, let's add a Ghidra script/console-specific handler.
    	var gsh = new GhidraScriptHandler(this);
    	Logging logging = new Logging(LOG_FILE_PATH, gsh, LOG_LEVEL, PREFIX_LOG_LEVEL);
    	if (logging == null || !logging.isSetupSuccess()) {
    		println("Logger setup not successful. Unable to continue.");
    		return;
    	}

    	try {
    		logger = Logger.getLogger("EHExtractor");
    		
    		// Can we actually handle this executable?
    		// The compiler has to be MSVC and the processor/bitness x86/32-bit.
    		if (!ProgramValidator.canAnalyze(currentProgram, logger)) {
    			return;
    		}
   
    		// To be able to resolve all CxxFrameHandler3 calls, we need to make sure the 
    		// "Shared Return Calls" analyzer has been run in such a way that all possible thunks
    		// have been found. The "Shared Return Calls" analyzer is part of the default set of
    		// analyzers that is run when doing an auto-analysis. It was found that when this 
    		// analyzer is run as part of the auto-analysis, it seems to be able to do only a
    		// partial job. The following call will (re)do the analysis and produce complete results.
    		SharedReturnCalls.discover(currentProgram, monitor, logger);

    		// Log global information about the file and set up some required internal objects.
    		var ehExtractor = new EHExtractor(currentProgram);
    		if (!ehExtractor.isAllOk()) {
    			return;
    		}
    		// Everything ready to go. Let's look for EH constructs!
    		ehExtractor.showFunctionInfos();

    	}
    	finally {
    		// Close the file used for logging.
    		logging.close();
    	}
    	
    }

}
