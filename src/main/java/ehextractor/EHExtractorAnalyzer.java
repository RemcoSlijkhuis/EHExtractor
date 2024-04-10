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

import java.util.logging.Level;
import java.util.logging.Logger;

import org.python.jline.internal.Log;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class EHExtractorAnalyzer extends AbstractAnalyzer {

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

		Logging logging = null;

		try {
			// Set up logging.
			logging = new Logging("C:\\Temp\\mylogfile.log", Level.ALL);
	    	if (logging == null || !logging.isSetupSuccess()) {
	    		Log.error("Logger setup not successful. Unable to continue.");
	    		return false;
	    	}

			var logger = Logger.getLogger("EHExtractor");
			logger.log(Level.INFO, "This is a test message.");
		}
		finally {
			logging.close();
		}
		
		return false;
	}
}
