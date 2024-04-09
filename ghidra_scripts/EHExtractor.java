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
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import instructionpatterns.*;
import loggingbridge.GhidraScriptHandler;
import msvc.exceptions.*;

public class EHExtractor extends GhidraScript {  
	final Level LOG_LEVEL = Level.ALL;

	Logger logger = null;
	FileHandler fh = null;
	
	Function cxxFrameHandler3 = null;
	
    public void run() throws Exception {
    	// Set up a proper logger first. Exit when there are problems doing so.
    	boolean success = setupLogger("C:\\Temp\\mylogfile.log");
    	if (!success) {
    		return;
    	}

    	// Program name and address space information.
    	Address minAddr = currentProgram.getMinAddress();
    	Address maxAddr = currentProgram.getMaxAddress();
    	logger.log(Level.INFO, "Program file: "+currentProgram.getExecutablePath());
    	logger.log(Level.INFO, "Program spans addresses "+minAddr+"-"+maxAddr);
    	
    	// Can we actually handle this executable? The compiler has to be MSVC and the processor/bitness x86/32-bit.
    	if (!checkCompiler(currentProgram)) {
    		logger.log(Level.INFO, "This executable was not compiled using MSVC.");
    		return;
    	}
    	if (!checkProcessorBitness(currentProgram)) {
    		logger.log(Level.INFO, "Executable should be for 32-bit x86, but is not.");    		
    		return;
    	}
    	logger.log(Level.INFO, "Executable is for 32-bit x86 and is compiled using MSVC.");

    	// If there are exceptions, we expect an exception handler. The main one for x86
    	// is CxxFrameHandler3. Look for this.
    	//
		// Note: In the current version of the executable, the JMP after the MOV EAX goes to ___CxxFrameHandler3
		//   (note the 3 underscores) at 00404004, where there is a JMP to __CxxFrameHandler3 (2 underscores)
		//   at 0040408c in vcruntime140.dll. ___CxxFrameHandler3 (3 underscores) is a thunk.
    	//
		// Find the function vcruntime*__CxxFrameHandler3.
    	logger.log(Level.FINE, "Determining the address of (thunk) function __CxxFrameHandler3.");
        cxxFrameHandler3 = findFunction("CxxFrameHandler3", "vcruntime", true);
        if (cxxFrameHandler3 == null) {
        	logger.log(Level.INFO, "Main exception handler function not found!");
			return;
        }


        logger.log(Level.FINE, "Now going to look at some functions.");
    	
    	List<Function> allFuncs = getInternalFunctions();
    	List<Function> myFuncs = allFuncs.stream()
    									 .filter(f -> f.getName().startsWith("THIS_IS_"))
    									 .collect(Collectors.toList());

    	myFuncs = allFuncs;
    	
		// Should check whether this function is used with 'call' or with 'jmp'.
		// If it is 'call' it should end with an RTS and when there is a JMP at
		// the end instead, this jump should be followed because the function
		// being jumped to is actually part of the function we're investigating!
	
		// Note that the description in Ghidra concerning the StackFrame is really
		// confusing! When the stack grows down, seen from the function's stack frame
		// base the parameters are higher in memory and the local variables lower;
		// hence, parameters should have a positive offset and local variables a
		// negative offset. However, the Ghidra documentation writes the opposite
		// but shows the correct polarity in the 'drawn' representation of the stack
		// when it grows down... and/but the stack as a whole is upside down in the 
		// 'drawn' representation.

    	for (var myFunc : myFuncs) {
    		logger.log(Level.INFO, "");
	        showFunctionInfo(myFunc);
    	}
    	
    	// Close the file used for logging.
    	if (fh != null)
    		fh.close();    	
    }

    private boolean setupLogger(String logfilePath) {
    	// First get rid of an annoying ConsoleHandler on a nameless logger
    	// that Ghidra apparently uses to dump horribly-formatted text (in red) at
    	// random places in the Eclipse Console when you use a logger.
    	removeAnnoyingConsoleHandler();

    	logger = Logger.getLogger("EHExtractor");

    	try {
    	    // Set a specific logging level.
    	    logger.setLevel(LOG_LEVEL);

    	    // When running the script in Ghidra again without having restarted Ghidra, the
    	    // logger will still be around and have handlers attached (even when having made
    	    // changes in Eclipse); we need to clean up these old handlers.
        	removeHandlers(logger);
    	    
    	    /* Configure the logger with handlers and formatters. */
        	// Output to a file.
    	    fh = new FileHandler(logfilePath, true);
    	    logger.addHandler(fh);
    	    
    	    // Output to the Ghidra console.
    	    var gsh = new GhidraScriptHandler(this);
    	    logger.addHandler(gsh);

    	    // The initial line should be different (like SimpleFormatter would do it).
    	    var initialLogFormatter = new MyLogFormatterInitial();
    	    fh.setFormatter(initialLogFormatter);
    	    gsh.setFormatter(initialLogFormatter);
    	    
    	    // Log the initial message. (Should end up like "Feb 11, 2024 11:27:23 AM EHExtractor".)
    	    logger.log(Level.INFO, "EHExtractor");

    	    // Switch to the normal formatter.
    	    var normalLogFormatter = new MyLogFormatter(true);
    	    fh.setFormatter(normalLogFormatter);
    	    gsh.setFormatter(normalLogFormatter);
    	}
    	catch (SecurityException | IOException e) {
    		println("An error occurred while setting up the logger: " + e.getMessage());
    		logger = null;
        	if (fh != null)
        		fh.close();
        	return false;
    	}
    	
    	return true;
    }
    
    private void removeAnnoyingConsoleHandler() {
    	LogManager manager = LogManager.getLogManager();
    	Logger loggr = manager.getLogger("");
    	var handlers = loggr.getHandlers();
	    for (int i = handlers.length-1; i>=0; i--) {
	    	var handler = handlers[i];
	    	if (handler instanceof java.util.logging.ConsoleHandler)
	    		loggr.removeHandler(handler);
	    }
    }
    
    private void listLoggerAndHandlerNames() {
    	LogManager manager = LogManager.getLogManager();
    	var loggerNames = manager.getLoggerNames();
    	while (loggerNames.hasMoreElements()) {
    		String loggerName = loggerNames.nextElement();
    		println("loggerName: " + loggerName);
        	Logger loggr = manager.getLogger(loggerName);
    		reportHandlers(loggr);
    	}
    }

    private void reportHandlers(Logger loggr) {
    	reportRemoveHandlers(loggr, true, false);
    }

    private void removeHandlers(Logger loggr) {
    	reportRemoveHandlers(loggr, false, true);
    }

    private void reportRemoveHandlers(Logger loggr, boolean report, boolean remove) {
	    if (loggr == null)
	    	return;
    	var handlers = loggr.getHandlers();
	    if (report)
	    	println("Nr handlers: " + handlers.length);
	    for (int i = handlers.length-1; i>=0; i--) {
	    	var handler = handlers[i];
	    	if (report)
	    		println("" + i + ": " + handler);
	    	if (remove)
	    		loggr.removeHandler(handler);
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

	private boolean checkCompiler(Program program) {
    	String usedCompiler = program.getCompiler();

    	CompilerSpec compilerSpec = program.getCompilerSpec();
    	CompilerSpecDescription compilerSpecDescription =  compilerSpec.getCompilerSpecDescription();
    	String compilerSpecName = compilerSpecDescription.getCompilerSpecName();
    	CompilerSpecID compilerSpecID = compilerSpecDescription.getCompilerSpecID();

    	logger.log(Level.FINE, "Compiler check:");

    	if (!usedCompiler.startsWith("visualstudio:")) {
    		return false;
    	}

    	if (!(compilerSpecName.equals("Visual Studio") && compilerSpecID.toString().equals("windows"))) {
    		return false;
    	}

    	return true;
	}
	
	private boolean checkProcessorBitness(Program program) {
    	CompilerSpec compilerSpec = program.getCompilerSpec();
    	Language sourceLanguage = compilerSpec.getLanguage();

    	// Some extra things.
    	//println("Language used: " + sourceLanguage);
    	//if (sourceLanguage.isBigEndian()) {
        //	println("  Big Endian");
    	//}
    	//else {
        //	println("  Little Endian");
    	//}
    	//println("Language produced: " + compilerSpec.getDecompilerOutputLanguage());
    	
    	Processor processor = sourceLanguage.getProcessor();
    	int pointerSize = sourceLanguage.getDefaultDataSpace().getPointerSize();

    	logger.log(Level.FINE, "Processor & bitness check:");
    	logger.log(Level.FINE, "  Processor type: " + processor);
    	logger.log(Level.FINE, "  Pointer size: " + 8*pointerSize + " bits");

		return processor.toString().equals("x86") && pointerSize == 4;
	}
	
	private List<Function> getInternalFunctions() {
    	List<Function> allFuncs = new ArrayList<Function>();
    	SymbolTable symtab = currentProgram.getSymbolTable();
    	SymbolIterator si = symtab.getSymbolIterator();
    	while (si.hasNext()) {
    		Symbol s = si.next();
    		if (s.getSymbolType() != SymbolType.FUNCTION || s.isExternal()) {
    			continue;
    		}
    		//println("Internal function: "+s.getName() + "  [0x" + s.getAddress() + "]");
    		Function func = getFunctionAt(s.getAddress());
    		allFuncs.add(func);
    	}
   		return allFuncs;
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
		if (!matchInstructionPatterns(startInstructions, instIter, false)) {
			logger.log(Level.INFO, "Normal start instructions not found!");
			return;
		}
		logger.log(Level.INFO, "Normal start instructions found!");

		logger.log(Level.FINE, "Looking for exception handling start instructions.");
		if (!matchInstructionPatterns(ehStartInstructions, instIter, false)) {
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
		//   so a JMP to the JMP CxxFrameHandler3 (stubbing).
		checkExceptionHandlerInstructions(listing, ehSetupAddress);
    }

    
    private void checkExceptionHandlerInstructions(Listing listing, Address ehSetupAddress) {

		Address ehFunctionInfoAddress = extractEHFunctionInfoAddress(listing, ehSetupAddress);
		if (ehFunctionInfoAddress == null)
			return;
		
		MSVCEHInfo msvcEHInfo = null;
		try {
			logger.log(Level.FINE, "About to process the EH data structures.");
			//msvcEHInfo = new MSVCEHInfo(currentProgram, ehFunctionInfoAddress);
			msvcEHInfo = MSVCEHInfoFactory.getMSVCEHInfo(currentProgram, ehFunctionInfoAddress);
			msvcEHInfo.analyze();
		}
		catch (InvalidDataTypeException e) { 
			logger.log(Level.SEVERE, "OH NOES! "+ e.getMessage());
		}
		
	}

	private Address extractEHFunctionInfoAddress(Listing listing, Address startAddress) {
		InstructionIterator instIt = listing.getInstructions(startAddress, true);

		// Check for cookie-checking code. Meaning of the return values: 0 means there is no such code,
		// 1 means there is but it is not standard/expected, 2 means there is and it is standard/expected.

		int cookieCheckPresent = lookForCookieCheckingCode(instIt);
		
		// If 0, we can go check for the EH registration code but should do this from the start iterator position (newAddress).
		// If 2, we can go check for the EH registration code from the current iterator position.
		// If 1, we could  go check for the EH registration code from the current iterator position, but we may run into
		// problems later on when parsing the the FuncInfo etc. data  structures (to be investigated further (are we seeing
		// part of the EH clean-up code?)).
		
		if (cookieCheckPresent == 0) {
			// Reset the instruction iterator.
			 instIt = listing.getInstructions(startAddress, true);
		}

		        
		// Exception handler function info registration.
		List<InstructionPattern> regInstructions = Arrays.asList(
				new ScalarInstructionPattern("MOV", "EAX", Scalar.class),
				new AddressInstructionPattern("JMP", cxxFrameHandler3, true)
		);
		
		logger.log(Level.FINE, "Looking for matching EH handler registration instructions.");
		if (!matchInstructionPatterns(regInstructions, instIt, true)) {
			logger.log(Level.INFO, "EH handler registration instructions not found!");
			return null;
		}
		logger.log(Level.INFO, "EH handler registration instructions found!");

		Scalar scalar = ((ScalarInstructionPattern)regInstructions.get(0)).getActualScalar();
		var ehFuncInfoAddress = makeAddress(scalar.getUnsignedValue());
		logger.log(Level.INFO, "Determined ehFuncInfoAddress: " + ehFuncInfoAddress);
		return ehFuncInfoAddress;
	}
	

	private int lookForCookieCheckingCode(InstructionIterator instIt) {
	
		logger.log(Level.FINE, "Looking up a security_check_cookie function.");
		Function securityCheckCookie = findFunction("security_check_cookie", null, true);
		if (securityCheckCookie != null) {
			logger.log(Level.FINE, "Found a security_check_cookie function: " + securityCheckCookie.getName() + " @" + securityCheckCookie.getEntryPoint());
		}
		else {
			logger.log(Level.FINE, "No clear security_check_cookie function found.");			
		}

		// Generic/flexible cookie-checking code instructions.
		List<InstructionPattern> cookieCheckInstructions = Arrays.asList(
				new AddressInstructionPattern("MOV", "EDX", "ESP", Scalar.class),
				new AddressInstructionPattern("LEA", "EAX", "EDX", (long)0xc),			
				new AddressInstructionPattern("MOV", "ECX", "EDX", Scalar.class), 
				new RegisterInstructionPattern("XOR", "ECX", "EAX"),
				new AddressInstructionPattern("CALL", securityCheckCookie, true)
		);
		logger.log(Level.FINE, "Looking for security cookie-checking code.");
		if (!matchInstructionPatterns(cookieCheckInstructions, instIt, true)) {
			logger.log(Level.FINE, "Cookie checking instructions not found!");
			return 0;
		}
		// There IS cookie-checking code.
		// Let's grab the scalar offsets so we can see if they are the expected/regular ones.
		var scalarOffset1 = ((AddressInstructionPattern)cookieCheckInstructions.get(0)).getScalarOffset();
		var scalarOffset2 = ((AddressInstructionPattern)cookieCheckInstructions.get(2)).getScalarOffset();
		
		// Regular cookie-checking code instructions?
		long regularScalarOffset1 = (long)0x8;
		long regularScalarOffset2 = (long)-0x18;

		if (scalarOffset1 != regularScalarOffset1 || scalarOffset2 != regularScalarOffset2) {
			logger.log(Level.FINE, "Regular cookie checking instructions not found, only irregular ones!");
			if (scalarOffset1 != (long)0x8) {
				logger.log(Level.FINE, "Scalar offset 1 irregular: " + scalarOffset1 + " instead of " + regularScalarOffset1);				
			}
			if (scalarOffset2 != (long)-0x18) {
				logger.log(Level.FINE, "Scalar offset 2 irregular: " + scalarOffset2 + " instead of " + regularScalarOffset2);				
			}
			return 1;
		}
		
		logger.log(Level.FINE, "Regular cookie checking instructions found!");
		return 2;		
	}

	private Function findFunction(String partialName, String partialParentNamespace, boolean dereferenceThunks) {
		partialName = partialName.toLowerCase();
		boolean checkParentNamespace = partialParentNamespace != null && !partialParentNamespace.isBlank();
	    if (checkParentNamespace) {
	        partialParentNamespace = partialParentNamespace.toLowerCase();
	    }
	    
        FunctionManager functionManager = currentProgram.getFunctionManager();
		SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

        var functionsByName = new ArrayList<Function>();
        var functionsByLabel = new ArrayList<Function>();
        
        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();

            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                // Get an actual Function object for this symbol.
                Function function = functionManager.getFunctionAt(symbol.getAddress());
                if (function == null)
                	continue;

                if (function.isThunk() && dereferenceThunks) {
                	//println("  Thunk: " + function.getName() + " @ " + function.getEntryPoint());
                	function = function.getThunkedFunction(true);
                	//println("  Thunked function: " + function.getName() + " @ " + function.getEntryPoint());
                }

            	if (!function.getName().toLowerCase().contains(partialName))
            		continue;

            	if (checkParentNamespace && !function.getParentNamespace().getName().toLowerCase().contains(partialParentNamespace))
            		continue;

            	if (!functionsByName.contains(function) ) {
                	functionsByName.add(function);
            	}
            }
            else if (symbol.getSymbolType() == SymbolType.LABEL &&  symbol.getName().toLowerCase().contains(partialName)) {
            	//println("  SYMBOL FOUND! " + symbol.getName());
            	//println("  --SymbolType: " + symbol.getSymbolType());
            	//println("  --Address: " + symbol.getAddress());
            	
            	Function function = functionManager.getFunctionAt(symbol.getAddress());
                if (function == null)
                	continue;

                //println("  --Function: " + function.getName());
            	//println("  --Function.isThunk(): " + function.isThunk());
            	//println("  --Function.getParentNamespace(): " + function.getParentNamespace());            	

                if (function.isThunk() && dereferenceThunks) {
                	//println("    xThunk: " + function.getName() + " @ " + function.getEntryPoint());
                	function = function.getThunkedFunction(true);
                	//println("    xThunked function: " + function.getName() + " @ " + function.getEntryPoint());
                }

            	if (checkParentNamespace && !function.getParentNamespace().getName().toLowerCase().contains(partialParentNamespace))
            		continue;

            	if (!functionsByLabel.contains(function) ) {
                	functionsByLabel.add(function);
            	}
            }            	
        }

        if (functionsByName.size() == 0) {
        	logger.log(Level.FINER, "  No functions found that match by name.");
        }
        else {
        	logger.log(Level.FINER, "  Functions found that match by name:");
            for (Function function : functionsByName) {
            	logger.log(Level.FINER, "    " + function + " @ " + function.getEntryPoint());
            }
        }

        if (functionsByLabel.size() == 0) {
        	logger.log(Level.FINER, "  No functions found that match by label.");
        }
        else {
        	logger.log(Level.FINER, "  Functions found that match by label:");
            for (Function function : functionsByLabel) {
            	logger.log(Level.FINER, "    " + function + " @ " + function.getEntryPoint());
            }
        }

       
        if (functionsByName.size() == 1) {
        	Function function = functionsByName.get(0);
        	logger.log(Level.FINER, "  Returning the 1 function that matched by name: " + function.getName());
        	return function;
        }
        else if (functionsByName.size() == 0 && functionsByLabel.size() == 1) {
        	Function function = functionsByLabel.get(0);
        	logger.log(Level.FINER, "  Returning the 1 function that matched by label (in the absence of a function matching by name): " + function.getName());
        	return function;
        }
        else if (functionsByName.size() > 0) {
        	Function function = functionsByName.get(0);
        	logger.log(Level.FINER, "  Returning the first function that matched by name: " + function.getName());
        	return function;
        }
        else if (functionsByLabel.size() > 0) {
        	Function function = functionsByLabel.get(0);
        	logger.log(Level.FINER, "  Returning the first function that matched by label (in the absence of functions matching by name): " + function.getName());
        	return function;
        }
        else {
        	logger.log(Level.FINER, "No matching function found.");
        }
        
        return null;
	}

	private Boolean matchInstructionPatterns(List<InstructionPattern> instructionPatterns, InstructionIterator instIter, boolean ignoreNops) {
        boolean matched = false;
        
        var nop = new NopInstructionPattern();
        
        int instPatternInd = 0;
        int actualInstInd = 0;
        while (instIter.hasNext() && !monitor.isCancelled()) {
        	Instruction inst = instIter.next();
        	logger.log(Level.FINE, String.format("%02d  ", actualInstInd) + inst.toString());

        	// TODO Handle the case where ignoreNops is true but one of the instruction patterns is actually a NOP.
        	if (ignoreNops) {        		
        		if (nop.matches(inst) ) {
        			actualInstInd++;
        			continue;
        		}
        	}
        	
        	if (!instructionPatterns.get(instPatternInd).matches(inst)) {
        		matched = false;
        		logger.log(Level.FINER, "Instructions not matched!");
    			break;
        	}

        	instPatternInd++;
        	actualInstInd++;

    		if (instPatternInd == instructionPatterns.size()) {
    			matched = true;
    			logger.log(Level.FINER, "All instructions matched!");
    			break;
    		}

        }
	    	
    	return matched;
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

	private String getCurrentTimeStamp() {
		// Default Java logging timestamp format (right?).
        SimpleDateFormat sdfDate = new SimpleDateFormat("MMM dd, yyyy HH:mm:ss a");
        Date now = new Date();
        return sdfDate.format(now);
    }
	
	private class MyLogFormatterInitial extends Formatter {
	    @Override
	    public String format(LogRecord record) {
	        // Custom format: Timestamp Message
	        return getCurrentTimeStamp() + " " + record.getMessage() + System.lineSeparator();
	    }
	}

	private class MyLogFormatter extends Formatter {
		private boolean showLevel = true;
		
		public MyLogFormatter(boolean showLevel) {
			this.showLevel = showLevel;
		}

		@Override
	    public String format(LogRecord record) {
			String msg = "";
			if (this.showLevel) {
				// Custom format: Log Level: Message
				msg = record.getLevel() + ": " + record.getMessage() + System.lineSeparator();
			}
			else {
				// Custom format: Message
				msg = record.getMessage() + System.lineSeparator();
			}
			return msg;
	    }
	}

}
