/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ehextractor;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.python.jline.internal.Log;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import msvc.exceptions.MSVCEHInfo;
import msvc.exceptions.MSVCEHInfoFactory;
import msvc.exceptions.code.EHHandler;
import msvc.exceptions.code.Prologue;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class EHExtractorAnalyzer extends AbstractAnalyzer {

	Program program = null;
	Prologue prologue = null;
	EHHandler ehHandler = null;

	Logger logger = null;
	
	public EHExtractorAnalyzer() {
		// TODO: Correct AnalyzerType? 
		super("EHExtractor", "Extracts x86 MSVC exception handling construct information.", AnalyzerType.FUNCTION_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// TODO: Change to false when shipping?
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// TODO: Examine 'program' to determine if this analyzer should analyze it.  Return true
		// if it can.

		var result = ProgramValidator.canAnalyze(program, null);		
		if (!result) {
			Log.info("EHExtractor cannot analyze the binary as it is not 32-bit x86 MSVC-compiled.");
		}		
		return result;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.

		this.program= program;

		Logging logging = null;


		try {
			// Set up logging.
			logging = new Logging("C:\\Temp\\mylogfile.log", Level.ALL);
	    	if (logging == null || !logging.isSetupSuccess()) {
	    		Log.error("Logger setup not successful. Unable to continue.");
	    		return false;
	    	}

			logger = Logger.getLogger("EHExtractor");

			// Program name and address space information.
    		Address minAddr = program.getMinAddress();
    		Address maxAddr = program.getMaxAddress();
    		logger.log(Level.INFO, "Program file: "+program.getExecutablePath());
    		logger.log(Level.INFO, "Program spans addresses "+minAddr+"-"+maxAddr);

    		// Create a Prologue instance.
    		prologue = new Prologue(program);

    		// Create an EHHandler instance suitable for the current program.
    		ehHandler = new EHHandler(program);
    		if (!ehHandler.isAllOk()) {
    			return false;
    		}

    		logger.log(Level.FINE, "Now going to look at some functions.");
    	
    		List<Function> allFuncs = FunctionUtils.getInternalFunctions(program);

    		for (var func : allFuncs) {
    			logger.log(Level.INFO, "");
    			showFunctionInfo(func);
    		}
    		
		}
		finally {
			logging.close();
		}
		
		return false;
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
			MSVCEHInfo msvcEHInfo = MSVCEHInfoFactory.getMSVCEHInfo(program, ehFuncInfoAddress);
			msvcEHInfo.analyze();
		}
		catch (InvalidDataTypeException e) { 
			logger.log(Level.SEVERE, "OH NOES! "+ e.getMessage());
		}
		
	}

}
