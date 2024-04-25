package ehextractor;

import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.app.cmd.analysis.SharedReturnAnalysisCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.task.TaskMonitor;

/**
 * This class provides an alternative way to 'run' the "Shared Return Calls" analyzer, which is
 * crucial for resolving calls to thunked functions, such as CxxFrameHandler3.
 * 
 * <p>This analyzer is typically run automatically during Ghidra's auto-analysis phase but has
 * been observed to yield incomplete results when executed in that context. Running this analyzer
 * after auto-analysis, either as part of a targeted re-analysis or as a single-shot process,
 * results in a much more complete outcome.</p>
 * 
 * <p>The method contained in this class allows one to manually trigger this analysis outside
 * of the auto-analysis sequence, thereby ensuring all relevant thunked functions can be resolved.</p>
 */
public class SharedReturnCalls {

	/**
     * Discovers and processes shared return calls within a given program. This method mimics the
     * behavior of the Ghidra "Shared Return Calls" analyzer by directly invoking the associated
     * analysis command and monitoring its execution until it finishes.
     * 
     * NOTE: This method is only suited to be run from a Ghidra script, not an analyzer!
     *
     * @param program The {@link Program} to analyze.
     * @param monitor A (dummy) {@link TaskMonitor} object. (The analyzer functionality was found to actually not use a monitor.)
     * @param logger A {@link Logger} to record some informational messages about the analysis progress.
     */
	public static void discover(Program program, TaskMonitor monitor, Logger logger) {
    	
		// Running the analyzer by scheduling it using the autoAnalysisManager did not produce
		// good results. Also, it requires specifying the analyzer by name which did not seem to
		// be the most stable approach. Therefore, we mimic what the analyzer does when it is called.
		logger.log(Level.INFO, "(Re-)Executing \"Shared Return Calls\".");
    	AddressSet set = new AddressSet(program.getMinAddress(), program.getMaxAddress());
    	SharedReturnAnalysisCmd cmd = new SharedReturnAnalysisCmd(set, true, false);
    	cmd.applyTo(program, monitor);

    	// Even though the analyzer was not started through the AutoAnalysisManager, we can still
    	// monitor the progress of the SharedReturnAnalysis command, presumably because the command
    	// uses the AutoAnalysisManager to create new functions.
    	AutoAnalysisManager autoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
    	if (!autoAnalysisManager.isAnalyzing()) {
    		logger.log(Level.INFO, "No new functions or thunks discovered.");
    	}
    	else {
    		logger.log(Level.INFO, "Waiting for discovered functions to be created.");
			// Wait for analysis to complete.
	        while (autoAnalysisManager.isAnalyzing()) {
	            try {
					Thread.sleep(100);
				}
	            catch (InterruptedException e) {
				}
	        }
       	}

	}
}
