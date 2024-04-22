package ehextractor;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import msvc.exceptions.MSVCEHInfo;
import msvc.exceptions.MSVCEHInfoFactory;
import msvc.exceptions.code.EHHandler;
import msvc.exceptions.code.Prologue;

/**
 * Highest-level class responsible for extracting MSVC exception handling information from a program.
 * Called from both the analyzer and the script.
 */
public class EHExtractor {
	private Logger logger = null;
	private Program program = null;
	private Prologue prologue = null;
	private EHHandler ehHandler = null;
	
	private boolean allOk = false;

	/**
     * Constructs an EHExtractor object for the given program.
     * @param program The program from which EH information is to be extracted.
     */
	public EHExtractor(Program program) {
		logger = Logger.getLogger("EHExtractor");
		this.program = program;
		init();
	}

	/**
     * Logs global program information (path, address range) and initializes components necessary for finding and extracting certain (MSVC) EH information.
     * Upon return it will be known whether or not we can continue with extracting EH information (checkable by isAllOk()).
     */
	private void init() {
		// Program name and address space information.
		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		logger.log(Level.INFO, "Program file: "+program.getExecutablePath());
		logger.log(Level.INFO, "Program spans addresses "+minAddr+"-"+maxAddr);

		// Create a Prologue instance.
		prologue = new Prologue(program);

		// Create an EHHandler instance suitable for the current program.
		ehHandler = new EHHandler(program);
		allOk = ehHandler.isAllOk();		
	}

	/**
     * Returns if the initial setup of the EHExtractor object was successful.
     * @return true if setup was successful, otherwise false.
     */
	public boolean isAllOk() {
		return allOk;
	}

	/**
     * Processes and outputs EH information (if present) for all functions in the program.
     */
	public void showFunctionInfos() {
    	logger.log(Level.FINE, "Now going to look at some functions.");
    	
    	List<Function> allFuncs = FunctionUtils.getInternalFunctions(program);
    	for (var func : allFuncs) {
			logger.log(Level.INFO, "");
			showFunctionInfo(func);
		}
    }

	/**
     * Processes and outputs EH information (if present) for a given function.
     * @param func The function to process.
     */
	private void showFunctionInfo(Function func) {
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
			MSVCEHInfo msvcEHInfo = MSVCEHInfoFactory.getMSVCEHInfo(program, ehFuncInfoAddress);
			msvcEHInfo.analyze();
		}
		catch (InvalidDataTypeException e) { 
			logger.log(Level.SEVERE, "An exception occurred processing the EH data structures. Unable to continue for this function.");
			logger.log(Level.SEVERE, "The exception message is: "+ e.getMessage());
		}
		
	}

}
