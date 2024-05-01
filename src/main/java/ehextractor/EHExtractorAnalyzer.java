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

import java.io.File;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.python.jline.internal.Log;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An analyzer that extracts x86 MSVC exception handling information from programs and writes it to a log file.
 * The log file path and the minimum log level can be set through the Analyzer options.
 */
public class EHExtractorAnalyzer extends AbstractAnalyzer {

	/**
	 * Enumerates the available minimum log levels to choose from.
	 */
	public enum LogLevelEnum {
	    FINER, FINE, INFO;
	}

	private static final String ANALYZER_NAME = "EHExtractor";

	private static final String OPTION_LOG_FILE_PATH = "Log file path";
	private static final String OPTION_LOG_LEVEL = "Minimum log level";
	private static final String OPTION_SHOW_LOG_LEVEL = "Prefix log level";

	private static final LogLevelEnum OPTION_LOG_LEVEL_DEFAULT = LogLevelEnum.INFO;
	private static final File OPTION_LOG_FILE_PATH_DEFAULT = Paths.get(System.getProperty("user.home"), "Documents", "ehextractor.log").toFile();
	private static final boolean OPTION_PREFIX_LOG_LEVEL_DEFAULT = false;

	private String logFilePath = null;
	private Level logLevel = Level.ALL;
	private boolean showLogLevel = true;
	
	Logger logger = null;
	
	public EHExtractorAnalyzer() {
		// We actually don't want this analyzer to be triggered in an automated fashion.
		// It makes the most sense to do this as a single-shot analysis.
		super("EHExtractor", "Extracts x86 MSVC exception handling construct information.", AnalyzerType.BYTE_ANALYZER);
		super.setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// Return false to prevent this analyzer from being triggered in an automated fashion.
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Check that the binary is an MSVC-compiled x86 binary.
		// Only then does it make sense to run this analyzer. 
		var result = ProgramValidator.canAnalyze(program, null);		
		if (!result) {
			Log.info("EHExtractor cannot analyze the binary as it is not 32-bit x86 MSVC-compiled.");
		}		
		return result;
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_LOG_LEVEL, OPTION_LOG_LEVEL_DEFAULT, null, "Minimum log level.");
		options.registerOption(OPTION_LOG_FILE_PATH, OptionType.FILE_TYPE, OPTION_LOG_FILE_PATH_DEFAULT, null, "Path to the log file.");
		options.registerOption(OPTION_SHOW_LOG_LEVEL, OPTION_PREFIX_LOG_LEVEL_DEFAULT, null, "Prefix output lines with their log level.");
	}

	@Override
	public void optionsChanged(Options options, Program programSoWhat) {
		var logFile = options.getFile(OPTION_LOG_FILE_PATH, null);
		logFilePath = logFile.getAbsolutePath();

		LogLevelEnum value = options.getEnum(OPTION_LOG_LEVEL, null);
		logLevel = convertLogLevel(value);
		
		showLogLevel = options.getBoolean(OPTION_SHOW_LOG_LEVEL, OPTION_PREFIX_LOG_LEVEL_DEFAULT);
	}

	private Level convertLogLevel(LogLevelEnum logLevel) {
	    switch (logLevel) {
	        case FINER:
	            return Level.FINER;
	        case FINE:
	            return Level.FINE;
	        case INFO:
	            return Level.INFO;
	        default:
	            return Level.INFO;
	    }
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		
		Msg.info(this, String.format("%s starting work on %s. Output log location is %s.", ANALYZER_NAME, program.getName(), logFilePath.toString()));
		
		// Start looking for (and logging) MSVC EH information in the given program. 
		Logging logging = null;
		try {
			// Set up logging.			
			logging = new Logging(logFilePath, logLevel, showLogLevel);
	    	if (logging == null || !logging.isSetupSuccess()) {
	    		Log.error("Logger setup not successful. Unable to continue.");
        		Msg.error(this, String.format("%s encountered a problem during logger setup. Check the output log at %s for more information.", ANALYZER_NAME, logFilePath.toString()));
	    		return false;
	    	}

    		// Log global information about the file and set up some required internal objects.
    		var ehExtractor = new EHExtractor(program);
    		if (!ehExtractor.isAllOk()) {
        		Msg.error(this, String.format("%s encountered a problem during setup. Check the output log at %s for more information.", ANALYZER_NAME, logFilePath.toString()));
    			return false;
    		}
    		// Everything ready to go. Let's look for EH constructs!
    		Msg.info(this, ANALYZER_NAME + " is looking for EH constructs.");
    		ehExtractor.showFunctionInfos();
    		Msg.info(this, String.format("%s finished. Output log location is %s.", ANALYZER_NAME, logFilePath.toString()));
		}
		finally {
    		// Close the file used for logging.
			logging.close();
		}
		
		return false;
	}
	
}
