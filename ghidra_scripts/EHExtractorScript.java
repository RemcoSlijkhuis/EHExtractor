//TODO Deze komt uit TestModuleProject
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 


import ghidra.app.script.GhidraScript;

import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import ehextractor.EHExtractor;
import ehextractor.Logging;
import ehextractor.ProgramValidator;

import loggingbridge.GhidraScriptHandler;

public class EHExtractorScript extends GhidraScript {  
	final Level LOG_LEVEL = Level.ALL;

	Logger logger = null;
	FileHandler fh = null;
		
    public void run() throws Exception {
    	// Set up a proper logger first. Exit when there are problems doing so.
    	// Note that the logger will by default log to a file but when we're running as a script,
    	// output to the console is very convenient. So, let's add a Ghidra script/console-specific handler.
    	var gsh = new GhidraScriptHandler(this);
    	Logging logging = new Logging("C:\\Temp\\mylogfile.log", gsh, LOG_LEVEL);
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


    		var ehExtractor = new EHExtractor(currentProgram);
    		if (!ehExtractor.isAllOk()) {
    			return;
    		}
    		ehExtractor.showFunctionInfos();

    	}
    	finally {
    		// Close the file used for logging.
    		logging.close();
    	}
    	
    }

}
