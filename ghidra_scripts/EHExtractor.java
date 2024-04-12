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

public class EHExtractor extends GhidraScript {  
	final Level LOG_LEVEL = Level.ALL;

	Logger logger = null;
	FileHandler fh = null;
	
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
    
    public void log(Level level, String msg) {
    	/*
    	// Write to the logger if set-up.
    	if (logger != null) {
    		logger.log(level, msg);
    	}
    	*/

    	if (level.intValue() >= LOG_LEVEL.intValue()) {
    		println(msg);
    	}
    }

    public void showFunctionInfo(Function func) {
    	logger.log(Level.INFO, "Looking at: "+func.getName());
        long addrStart = func.getBody().getMinAddress().getOffset();
        long addrEnd = func.getBody().getMaxAddress().getOffset();
        logger.log(Level.INFO, String.format("Memory range: %08x-%08x", addrStart, addrEnd));

        logger.log(Level.FINE, "Let's start with the instructions:");

        // Function start.  
		List<InstructionPattern> startInstructions = Arrays.asList(
				new RegisterInstructionPattern("PUSH", Arrays.asList("EBP")),
				new RegisterInstructionPattern("MOV", Arrays.asList("EBP", "ESP")));

        // Exception handling start instructions. The rest of the EH-setup instructions are only
        // relevant during runtime so they are ignored here.
        List<InstructionPattern> ehStartInstructions = Arrays.asList(
        		new ScalarInstructionPattern("PUSH", -1),
        		new ScalarInstructionPattern("PUSH", null)); 
        
         
    	Listing listing = currentProgram.getListing();
        InstructionIterator instIter = listing.getInstructions(func.getBody(), true);

		logger.log(Level.FINE, "Looking for standard function prologue.");
		if (!InstructionPatterns.match(startInstructions, instIter, false).isMatched()) {
			logger.log(Level.INFO, "Normal start instructions not found!");
			return;
		}  
		logger.log(Level.INFO, "Normal start instructions found!");

		logger.log(Level.FINE, "Looking for exception handling start instructions.");
		if (!InstructionPatterns.match(ehStartInstructions, instIter, false).isMatched()) {
			logger.log(Level.INFO, "Exception handling start instructions not found!");
			return;
		}
		logger.log(Level.INFO, "Exception handling start instructions found!");
        
        
		// Determine the address that's pushed onto the stack.
		//Scalar ehPointer = (Scalar)inst.getOpObjects(0)[0];
		Scalar ehPointer = ((ScalarInstructionPattern)ehStartInstructions.get(1)).getActualScalar();
		Address ehSetupAddress = makeAddress(ehPointer);
		logger.log(Level.FINE, "Going to look at the supposed EH setup code at location "+ehSetupAddress.toString(true));
		// There should be a certain set of instructions at this location.
		//- You'd think that would have been made into a function, but it's not.
		//- I think Ghidra determines what a function is based on recognized prologues (and that's not here).

		// Should evaluate the instructions: do they match with expectations?
		// Do we at least see registering of an ehFuncInfo?  Is cookie-checking code included or not?
		// Note: registering involves putting an address in EAX and JMPing to CxxFrameHandler3,
		//   but this JMP may not follow the MOV EAX immediately; there may be an extra JMP in between,
		//   so a JMP to the JMP CxxFrameHandler3 (thunking).
		checkExceptionHandlerInstructions(listing, ehSetupAddress);
    }

    
    private void checkExceptionHandlerInstructions(Listing listing, Address ehSetupAddress) {

    	Address ehFuncInfoAddress = ehHandler.extractFuncInfoAddress(listing, ehSetupAddress);
		if (ehFuncInfoAddress == null)
			return;
		
		MSVCEHInfo msvcEHInfo = null;
		try {
			logger.log(Level.FINE, "About to process the EH data structures.");
			msvcEHInfo = MSVCEHInfoFactory.getMSVCEHInfo(currentProgram, ehFuncInfoAddress);
			msvcEHInfo.analyze();
		}
		catch (InvalidDataTypeException e) { 
			logger.log(Level.SEVERE, "OH NOES! "+ e.getMessage());
		}
		
	}

	public Address makeAddress(Scalar scalar) {
		// TODO return toAddr(scalar.getUnsignedValue());
    	return makeAddress(scalar.getUnsignedValue());
    }

    public Address makeAddress(long address) {
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
		Address newAddress = defaultAddressSpace.getAddress(address);
		return newAddress;
    }

	private String getBytesString(MemBuffer memBuffer, int numBytes) {
		List<Byte> bytes = getBytes(memBuffer, numBytes);
		
		StringBuilder sb = new StringBuilder();
		for (Byte bite : bytes) {
			if (bite != null)
				sb.append(String.format("%02x", bite));
			else
				sb.append("??");
		    sb.append(" ");
		}
		String bytesString = sb.toString().trim();

		return bytesString;
	}


	private List<Byte> getBytes(MemBuffer memBuffer, int numBytes) {
		List<Byte> bytes = new ArrayList<Byte>();

		for (int i=0; i<numBytes; i++) {
			Byte bite = null;
			try {
				bite = memBuffer.getByte(i);
			} catch (MemoryAccessException e) {
			}
			bytes.add(bite);
		}

		return bytes;
	}

}
