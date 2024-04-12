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

public class EHExtractor extends GhidraScript {  
	final Level LOG_LEVEL = Level.ALL;

	Logger logger = null;
	FileHandler fh = null;
	
	Prologue prologue = null;
	EHHandler ehHandler = null;
	
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

    		// Program name and address space information.
    		Address minAddr = currentProgram.getMinAddress();
    		Address maxAddr = currentProgram.getMaxAddress();
    		logger.log(Level.INFO, "Program file: "+currentProgram.getExecutablePath());
    		logger.log(Level.INFO, "Program spans addresses "+minAddr+"-"+maxAddr);

    		// Create a Prologue instance.
    		prologue = new Prologue(currentProgram);

    		// Create an EHHandler instance suitable for the current program.
    		ehHandler = new EHHandler(currentProgram);
    		if (!ehHandler.isAllOk()) {
    			return;
    		}


    		logger.log(Level.FINE, "Now going to look at some functions.");
    	
    		List<Function> allFuncs = FunctionUtils.getInternalFunctions(currentProgram);

    		for (var func : allFuncs) {
    			logger.log(Level.INFO, "");
    			showFunctionInfo(func);
    		}
    	}
    	finally {
    		// Close the file used for logging.
    		logging.close();
    	}
    	
    }

    public void showFunctionInfo(Function func) {
    	// Show the name and memory location range of the function.
    	logger.log(Level.INFO, "Looking at: "+func.getName());
        long addrStart = func.getBody().getMinAddress().getOffset();
        long addrEnd = func.getBody().getMaxAddress().getOffset();
        logger.log(Level.INFO, String.format("Memory range: %08x-%08x", addrStart, addrEnd));

        logger.log(Level.FINE, "Let's start with the instructions:");

        // Look at the start of the function; does it have the expected format?
        // If so, get the address of 'ehhandler' / the 'EH setup code'.
		Address ehSetupAddress = prologue.extractEHSetupAddress(func);
		if (ehSetupAddress == null)
			return;
		
		logger.log(Level.FINE, "Going to look at the supposed EH setup code at location "+ehSetupAddress.toString(true));

		// We have a location! There should be a certain set of instructions there.
		// Should evaluate the instructions: do they match with expectations?
		// Do we at least see registering of an ehFuncInfo?  Is cookie-checking code included or not?
		// Note: registering involves putting an address in EAX and JMPing to CxxFrameHandler3,
		//   but this JMP may not follow the MOV EAX immediately; there may be an extra JMP in between,
		//   so a JMP to the JMP CxxFrameHandler3 (thunking).

    	// If our expectations are met, we can get FuncInfo's memory location.
    	Address ehFuncInfoAddress = ehHandler.extractFuncInfoAddress(ehSetupAddress);
		if (ehFuncInfoAddress == null)
			return;
		
		// With the location of the FuncInfo data structure found, let's try
		// to parse it and the connected data structures.
		try {
			logger.log(Level.FINE, "About to process the EH data structures.");
			MSVCEHInfo msvcEHInfo = MSVCEHInfoFactory.getMSVCEHInfo(currentProgram, ehFuncInfoAddress);
			msvcEHInfo.analyze();
		}
		catch (InvalidDataTypeException e) { 
			logger.log(Level.SEVERE, "OH NOES! "+ e.getMessage());
		}
		
	}

}
