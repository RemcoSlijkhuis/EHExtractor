//TODO Deze komt uit TestModuleProject
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 



import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import ehextractor.EHExtractor;
import ehextractor.FunctionUtils;
import ehextractor.Logging;
import ehextractor.ProgramValidator;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import instructionpattrns.*;
import loggingbridge.GhidraScriptHandler;
import msvc.exceptions.*;
import msvc.exceptions.code.EHHandler;
import msvc.exceptions.code.Prologue;

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