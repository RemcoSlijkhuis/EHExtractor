package msvc.exceptions;

import ghidra.program.model.data.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Top-level representation of the exception handling information for individual functions in Microsoft Visual C++-compiled binaries
 * that can be derived from the various EH-related data structures used.
 */
public class MSVCEHInfo {

	Logger logger = null;

	private int magicNumber = 0;
	private int bbtFlags = 0;
	private int maxState = 0;
	private Address pUnwindMap = null;
	private int nTryBlocks = 0;
	private Address pTryBlockMap = null;
	private int nIPMapEntries = 0;
	private Address pIPToStateMap = null;
	private Address pESTypeList = null;
	private int ehFlags = 0;

	private List<TryBlockMapEntry> tryBlockMapEntries = null;
	private UnwindMap unwindMap = null;

	/**
     * Creates an MSVCEHInfo instance which represents the FuncInfo data structure, extended with
     * information and objects derived from the data structures linked to FuncInfo.
     *
     * @param magicNumber The "compiler version identifier" (but really more an identifier of which kinds of EH are supported).
     * @param bbtFlags "Flags that may be set by BBT processing."
     * @param maxState Number of entries in the unwind map.
     * @param pUnwindMap Address of the unwind map.
     * @param nTryBlocks Number of try blocks.
     * @param pTryBlockMap Address of the TryBlockMap.
     * @param nIPMapEntries "Number of IP-to-state map entries."
     * @param pIPToStateMap Address of the "IP-to-state map".
     * @param pESTypeList Address of the ESTypeList.
     * @param ehFlags Flags for some specific EH-related features.
     * @param unwindMap An UnwindMap instance, derived from the linked UnwindMap data structure.
     * @param tryBlockMapEntries The list of TryBlockMapEntries, derived from the linked TryBlockMap data structure.
     */
	public MSVCEHInfo(int magicNumber, int bbtFlags, int maxState, Address pUnwindMap, int nTryBlocks,
			Address pTryBlockMap, int nIPMapEntries, Address pIPToStateMap, Address pESTypeList, int ehFlags,
			UnwindMap unwindMap, List<TryBlockMapEntry> tryBlockMapEntries) {
		logger = Logger.getLogger("EHExtractor");

		this.magicNumber = magicNumber;
		this.bbtFlags = bbtFlags;
		this.maxState = maxState;
		this.pUnwindMap = pUnwindMap;
		this.nTryBlocks = nTryBlocks;
		this.pTryBlockMap = pTryBlockMap;
		this.nIPMapEntries = nIPMapEntries;
		this.pIPToStateMap = pIPToStateMap;
		this.pESTypeList = pESTypeList;
		this.ehFlags = ehFlags;
		this.tryBlockMapEntries = tryBlockMapEntries;
		this.unwindMap = unwindMap;
	}

	/**
	 * Tries to determine the try/catch block layout based on the tryBlockMapEntries and the unwindMap.
	 *
	 * @throws InvalidDataTypeException If there is a state mismatch or other processing error.
	 */
	public void analyze() throws InvalidDataTypeException {
		if (tryBlockMapEntries == null) {
			logger.log(Level.INFO, "No TryBlockMapEntries to analyze.");
			return;
		}

		// Determine the layout of the try/catch blocks as much as possible just from the tryBlockMap.
		ArrayList<TryBlockMapEntry> outerTryBlockMapEntries = determineLayout(tryBlockMapEntries);

		// Show what we now know about the try/catch block structures.
		displayTryCatchBlockOverview(outerTryBlockMapEntries, "Try/catch block overview, after determineLayout but without unwind information applied:", Level.FINE);

		// About states:
		// It is trivial to know the state used for each try block (it's the tryLow value), but the states of catch
		// blocks are a bit more involved.
		// Without nesting in a catch block, it seems obvious that its state is the catchHigh value, which happens
		// to equal tryHigh+1. But WITH nesting you cannot depend on the catchHigh value anymore (as the 
		// try/catch-blocks nested in the catch block influence this number); instead, it looks like it actually 
		// might be tryHigh+1 if you look at the gaps in state numbers left by known try/catch blocks (and a cursory
		// glance at Microsoft's EH source code).
		// Of course you can/will find out the catch block states when stepping through the compiled code, but there is
		// another data structure that can be used to determine these states (and to double check the ones for the
		// try blocks) beforehand: the unwind information!
		// This unwind information contains (/seems to contain) the next state to look at for trying to find the
		// handler for the current exception when none of the catch blocks in the try in which the exception occurred
		// is appropriate. (NB: If the exception happened in a function outside of a try block in that function,
		// the EH code will look for a handler in the calling functions.).
					
		if (unwindMap == null) {
			logger.log(Level.FINE, "No unwind information to apply.");
			return;
		}

		// Refine and double-check the layout of the try/catch blocks by applying unwind information.
		logger.log(Level.FINE, "Applying unwind information.");
		for (int i=0; i<unwindMap.getCount(); i++) {
			logger.log(Level.FINER, "From " + i + " to " + unwindMap.getToState(i));
		}
		HashSet<Integer> knownStates = new HashSet<Integer>();
		for (var outer : outerTryBlockMapEntries) {
			recurse(outer, null, knownStates, unwindMap, "");
		}
		
		// Display the final version of the overview after having added the information from the unwind map.
		displayTryCatchBlockOverview(outerTryBlockMapEntries, "Try/catch block overview:", Level.INFO);
	}
	
	/**
	 * Logs an overview of the (possibly nested) try/catch block layout from the given TryBlockMapEntries.
	 *
	 * @param outerTryBlockMapEntries The list of TryBlockMapEntries to derive the layout overview from.
	 * @param header A header line to include as the first line to the overview.
	 */
	private void displayTryCatchBlockOverview(List<TryBlockMapEntry> outerTryBlockMapEntries, String header, Level logLevel) {
		List<String> lines = getTryCatchBlockOverview(outerTryBlockMapEntries, header);
		for (String line : lines) {
			logger.log(logLevel, line);
		}
	}

	/**
	 * Generates a list of strings with an overview of the (possibly nested) try/catch block layout from the given TryBlockMapEntries.
	 *
	 * @param outerTryBlockMapEntries The list of TryBlockMapEntries to derive the layout overview from.
	 * @param header A header line to include as the first line to the overview.
	 * @return A list of strings with the try/catch block layout.
	 */
	public static List<String> getTryCatchBlockOverview(List<TryBlockMapEntry> outerTryBlockMapEntries, String header) {
		List<String> lines = new ArrayList<String>();
		lines.add(header);
		var tryLowComparator =  new TryLowComparator();
		Collections.sort(outerTryBlockMapEntries, tryLowComparator);
		for (var outer : outerTryBlockMapEntries) {
			var infoLines = outer.getNestingInfoLines();
			lines.addAll(infoLines);
		}
		return lines;
	}

	/**
	 * Determines the layout of the try/catch blocks as much as possible just from TryBlockMapEntries.

	 * @param tryBlockMapEntries The TryBlockMapEntries from which to derive the try/catch layout.
	 * @return A list of 'outer' TryBlockMapEntries; any nested entries will have been added as such to these outer ones.
	 */
	public static ArrayList<TryBlockMapEntry> determineLayout(List<TryBlockMapEntry> tryBlockMapEntries) {
		Logger.getLogger("EHExtractor").log(Level.FINE, "Going to look for nested try/catch blocks using the contents of the TryBlockMapEntry array.");

		// Sort the tryBlockMapEntries in DESCENDING order of their tryLow values.
		// This takes into account the observed ordering of state values the compiler imposes.
		// By processing the TryBlockMapEntries in descending order of their tryLow values,
		// we ensure that we start with the last/deepest nested try/block maps first, making
		// the determination of parents and nesting simpler and more performant, compared
		// to an unsorted approach.
		var tryLowComparator =  new TryLowComparator();
		Collections.sort(tryBlockMapEntries, tryLowComparator.reversed());

		var todo = new ArrayList<TryBlockMapEntry>();

		for (var tryBlockMapEntry : tryBlockMapEntries) {
			var tryHigh = tryBlockMapEntry.getTryHigh();
			var catchHigh = tryBlockMapEntry.getCatchHigh();

			// If this is a leaf, it can only be nested itself inside another try or catch block we haven't encountered yet: put it on the todo list.
			var isLeaf = tryBlockMapEntry.isLeaf();
			if (isLeaf) {
				todo.add(tryBlockMapEntry);
				continue;
			}

			// Ok, it's not a leaf; it can contain other try/catch blocks in its try and/or catch blocks.
			var toBeRemoved = new ArrayList<TryBlockMapEntry>();
			for (var prev : todo) {
				// prev's full state span is [pre.tryLow, max(pre.tryHigh, pre.catchHigh)]. If this is fully contained in the
				// current try block's state span [current.tryLow, current.tryHigh], this previous try/catch block is nested in
				// the current try block.
				if (tryBlockMapEntry.getTryStateRange().contains(prev.getStateRange())) {
					// This previous try/catch block is nested in the current try block.
					tryBlockMapEntry.nestInTry(prev);  // TODO sort!
					toBeRemoved.add(prev);
					continue;
				}
				else if (tryHigh <= prev.getCatchHigh() && prev.getCatchHigh() <= catchHigh) {  // TODO tryHigh < ?
					// This previous try/catch block is nested in one of the current catch blocks.
					tryBlockMapEntry.nestInCatches(prev); // TODO sort!
					toBeRemoved.add(prev);
					continue;
				}
			}
			for (var prev : toBeRemoved) {
				todo.remove(prev);
			}
			todo.add(tryBlockMapEntry);			
		}
		// The todo list should now contain only outermost-level try/catch blocks for the function.

		return todo;
	}
	
	/**
	 * Recursively determines nested try and catch block layout starting from a given TryBlockMapEntry,
	 * incorporating unwind information to find catch block states and to double-check try block states.
	 *
	 * @param current The current TryBlockMapEntry being processed.
	 * @param parent The parent (TryBlock or CatchHandler) for current; may be null if current is the root.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @throws InvalidDataTypeException If there is a state mismatch or other processing error.
	 */
	public static void recurse(TryBlockMapEntry current, ITryCatch parent, HashSet<Integer> knownStates, UnwindMap unwindMap, String prefix) throws InvalidDataTypeException {
		var logger = Logger.getLogger("EHExtractor");

		// Display some debugging info.
		logInitialDebuggingInfo(current, parent, prefix, logger);

		// This function is about applying unwind information, so if we don't have it, there's nothing to do.
		if (unwindMap == null || unwindMap.getCount() == 0) {
			logger.log(Level.FINE, prefix+"No unwind map information; nothing to do.");
			return;
		}
		
		// Handle the try block and everything nested in it.
		var targetToState = handleTryBlock(current, unwindMap, knownStates, prefix, logger);
		
		// If we have a parent, check that its state matches tryToState. If it does not have a valid state yet, set it (to targetToState). 
		checkAndSetParentState(parent, targetToState, knownStates, prefix, logger);

		// Handle the catch blocks and everything in them.
		handleCatchBlocks(current, parent, targetToState, knownStates, unwindMap, prefix, logger);
	}

	/**
	 * Displays some debugging info specific to the start of the 'recurse' method.
	 * 
	 * @param current The current TryBlockMapEntry being processed.
	 * @param parent The parent (TryBlock or CatchHandler) for current; may be null if current is the root.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 */
	private static void logInitialDebuggingInfo(TryBlockMapEntry current, ITryCatch parent, String prefix, Logger logger) {
		logger.log(Level.FINE, prefix+"Current: " + current.getHeaderInfoLine());
		logger.log(Level.FINE, prefix+"Nesting in try: " + current.nestingInTry());
		logger.log(Level.FINE, prefix+"Nesting in catches: " + current.nestingInCatches());
		if (parent != null) {
			logger.log(Level.FINE, prefix+"Parent is a " + parent.getBlockType());
		}
		else {
			logger.log(Level.FINE, prefix+"Parent is null.");
		}
	}
	
	/**
	 * Recursively handles current's try block and everything nested in it.
	 * 
	 * @param current The current TryBlockMapEntry being processed.
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @return The state current's try block unwinds to.
	 * @throws InvalidDataTypeException If there is a problem determining the state of a try or catch block. 
	 */
	private static Integer handleTryBlock(TryBlockMapEntry current, UnwindMap unwindMap, HashSet<Integer> knownStates,
										  String prefix, Logger logger) throws InvalidDataTypeException {

		// Handle the try block and everything nested in it.
		logger.log(Level.FINE, prefix+"Looking at current's try block. State is " + current.getTryLow());
		
		// First do everything nested in the current try block.
		processTryBlockNestlings(current, unwindMap, knownStates, prefix, logger);

		// Now handle the current try block itself.
		var targetToState = processTryBlock(current, unwindMap, knownStates, prefix, logger);
		return targetToState;
	}

	/**
	 * Recursively processes all TryCatchBlockEntries nested in current's try block.
	 * 
	 * @param current The current TryBlockMapEntry being processed.
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @throws InvalidDataTypeException If there is a problem determining the state of a try or catch block. 
	 */
	private static void processTryBlockNestlings(TryBlockMapEntry current, UnwindMap unwindMap, HashSet<Integer> knownStates,
												 String prefix, Logger logger) throws InvalidDataTypeException {

		// First do everything nested in the current try block.
		if (current.nestingInTry()) {
			logger.log(Level.FINE, prefix+"Going into try/catches nested in current's try block.");
			// We need to have the states of all try blocks that are direct descendants of the current try block
			// in order to assign the proper states to their catch blocks. That's why we collect these states
			// before calling recurse for each 'try child'.
			for (var child : current.getNestedInTry()) {
				knownStates.add(child.getTryLow());
			}
			for (var child : current.getNestedInTry()) {
				recurse(child, current.getTryBlock(), knownStates, unwindMap, prefix+"  ");
			}
		}
	}

	/**
	 * Determines the target state current's try block unwinds to.
	 * 
	 * @param current The current TryBlockMapEntry being processed.
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @return The state current's try block unwinds to.
	 * @throws InvalidDataTypeException If there is a problem with the unwind map.
	 */
	private static Integer processTryBlock(TryBlockMapEntry current, UnwindMap unwindMap, HashSet<Integer> knownStates,
										   String prefix, Logger logger) throws InvalidDataTypeException {

		// Now handle the current try block itself.
		logger.log(Level.FINE, prefix+"Handling current's try block.");

		// Get the state of the try block for the current TryBlockMapEntry and look
		// up the state to which it will unwind; it should match the state of its parent.
		var tryState = current.getTryBlock().getState();
		var targetToState = unwindMap.getToState(tryState);
		logger.log(Level.FINE, prefix+"Current try state "+tryState+" unwinds to toState "+targetToState);
		knownStates.add(tryState);
		return targetToState;
	}


	/**
	 * Recursively determines the states of all catch blocks of a TryBlockMapEntry.
	 * 
	 * @param current The TryBlockMapEntry for which all catch blocks (unnested, nested, and to-be-nested) need to be processed.
	 * @param parent The parent TryBlock or CatchHandler for current.
	 * @param targetToState The state the catch block needs to unwind to.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @throws InvalidDataTypeException If there is a problem determining the states of the catch blocks. 
	 */
	private static void handleCatchBlocks(TryBlockMapEntry current, ITryCatch parent, Integer targetToState,
			HashSet<Integer> knownStates, UnwindMap unwindMap, String prefix, Logger logger)
			throws InvalidDataTypeException {
		// First handle anything that is nested in this TryBlockMapEntry's catch blocks. 
		if (current.nestingInCatches()) {
			processNestedCatchBlocks(current, unwindMap, knownStates, prefix, logger);
		}
		
		// Now handle the current TryBlockMapEntry's catches.
		logger.log(Level.FINE, prefix+"Handling current's catch blocks.");

		// We should have a valid parent state (if we have a parent) because we handled the try block first
		// (and a state mismatch would have resulted in an exit), but let's double-check.
		checkParentState(parent, prefix, logger);

		logger.log(Level.FINE, prefix + "targetToState determined to be " + targetToState);
		
		// A TryBlockMapEntry may have multiple catch blocks. If we were to store the state of the
		// first catch block we determine in knownStates, we would not be able to determine the
		// states of the other catch blocks in the same TryBlockMapEntry anymore. Therefore, we keep
		// track of the newly assigned catch block states in a separate variable.
		List<Integer> currentsNewCatchBlockStates = new ArrayList<Integer>();

		// Loop over all catch blocks in this TryBlockmapEntry and try to find their state values
		// if we don't have them yet.
		for (var catchHandler : current.getCatchHandlers()) {
			processCatchBlock(catchHandler, current, unwindMap, targetToState, knownStates, currentsNewCatchBlockStates, prefix, logger);
		}
	}

	/**
	 * Recursively determines the states of all nested and to-be-nested catch blocks of a TryBlockMapEntry.
	 * 
	 * @param current The TryBlockMapEntry for which the nested and to-be-nested catch blocks need to be processed.
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @throws InvalidDataTypeException If there is a problem determining the catch block state. 
	 */
	private static void processNestedCatchBlocks(TryBlockMapEntry current, UnwindMap unwindMap,
			HashSet<Integer> knownStates, String prefix, Logger logger) throws InvalidDataTypeException {
		logger.log(Level.FINE, prefix+"Going into try/catches nested in current's catch blocks.");
		// Some TryBlockMapEntries may already be nested in specific catch handlers. Let's do these first.
		for (var catchHandler : current.getCatchHandlers()) {
			for (var child : catchHandler.getNested()) {
				recurse(child, catchHandler, knownStates, unwindMap, prefix+"  ");
			}
		}
		// For other TryBlockMapEntries, we may know that they are nested in some catch handler(s), but we
		// don't know in which.
		for (var child : current.getToBeNestedInCatches()) {
			// TODO The parent is null here, which may pose problems in some cases; I think...
			recurse(child, null, knownStates, unwindMap, prefix+"  ");
		}
	}

	/**
	 * Determines the states of all unnested catch blocks of a TryBlockMapEntry.
	 * 
	 * @param catchHandler The CatchHandler for which the state must be determined.
	 * @param current The current TryBlockMapEntry (of which catchHandler is a part).
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param targetToState The state the catch block needs to unwind to.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param currentsNewCatchBlockStates The newly assigned catch block states.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @throws InvalidDataTypeException If there is a problem determining the catch block state. 
	 */
	private static void processCatchBlock(CatchHandler catchHandler, TryBlockMapEntry current, UnwindMap unwindMap,
										  Integer targetToState, HashSet<Integer> knownStates, List<Integer> currentsNewCatchBlockStates,
										  String prefix, Logger logger) throws InvalidDataTypeException {

		// If we already know this catch block's state there is no need to do anything.
		if (catchHandler.hasValidState()) {
			logger.log(Level.FINE, prefix+"State already determined for this catch block (it's "+catchHandler.getState()+").");
			return;
		}
		// Get the list of all 'from' states that have not been assigned to a try or catch block yet AND that
		// unwind to the correct state (targetToState) AND that are higher than the try block's state.
		// One of these must be the 'from state' for this catch block.
		List<Integer> possibleStates = filterFromStates(unwindMap, knownStates, targetToState, current.getTryHigh());

		// Display some debugging information about the known states and the possible catch block states.
		logger.log(Level.FINE, prefix+String.format("- Current try state: %d", current.getTryLow()));
		logStates(knownStates, possibleStates, prefix, logger);

		// Now determine the state of the current catch block.
		handleCatchStateAssignment(catchHandler, current, knownStates, possibleStates, currentsNewCatchBlockStates, prefix, logger);
	}
	
	/**
	 * Determines the state value of a catch block.
	 * 
	 * @param catchHandler The CatchHandler for which the state must be determined.
	 * @param current The current TryBlockMapEntry (of which catchHandler is a part).
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block).
	 * @param possibleStates The list of possible catch block states.
	 * @param currentsNewCatchBlockStates The newly assigned catch block states.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @throws InvalidDataTypeException If there is a problem determining the catch block state. 
	 */
	private static void handleCatchStateAssignment(CatchHandler catchHandler, TryBlockMapEntry current, 
												   HashSet<Integer> knownStates, List<Integer> possibleStates, 
												   List<Integer> currentsNewCatchBlockStates,
												   String prefix, Logger logger) throws InvalidDataTypeException {
		if (possibleStates.size() == 0 && currentsNewCatchBlockStates.size() != 1) {
			var msg = "Did not find any possible states for catch blocks!";
			logger.log(Level.SEVERE, prefix+msg);
			throw new InvalidDataTypeException(msg);
		}
		else if (possibleStates.size() == 0 && currentsNewCatchBlockStates.size() == 1) {
			logger.log(Level.FINE, prefix+"No new state available but we found one state for an earlier catch block at this level; going to use that.");
			var catchState = currentsNewCatchBlockStates.get(0);
			assignCatchState(catchHandler, catchState, prefix, logger);
			return;
		}
		else if (possibleStates.size() == 1) {
			logger.log(Level.FINE, prefix+"Found one state for the catch block(s).");
			var catchState = possibleStates.get(0);
			assignCatchState(catchHandler, catchState, knownStates, currentsNewCatchBlockStates, prefix, logger);
		}
		else {
			var msg = "Still have multiple possible states for catch blocks! Doing some more checking.";
			logger.log(Level.FINE, prefix+msg);
			
			// It can be really simple and be a leaf; we're going depth-first after all.
			if (current.isLeaf()) {
				var catchState = current.getTryHigh()+1;
				if (possibleStates.contains(catchState)) {
					assignCatchState(catchHandler, catchState, knownStates, currentsNewCatchBlockStates, prefix, logger);
					return;
				}
			}					
			
			msg = "No, cannot determine the catch block state!";
			throw new InvalidDataTypeException(msg);
		}
	}

	/**
	 * Sets the state for the given CatchHandler to the given value.
	 * 
	 * @param catchHandler The CatchHandler for which to set the state.
	 * @param catchState The state to set for catchHandler.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 */
	private static void assignCatchState(CatchHandler catchHandler, Integer catchState, String prefix, Logger logger) {
		logger.log(Level.FINE, prefix+"Setting this catch block's state to " + catchState);
		catchHandler.setState(catchState);
	}

	/**
	 * Sets the state for the given CatchHandler to the given value. Updates the list of 'known' states and the list of newly assigned catch block states.
	 * 
	 * @param catchHandler The CatchHandler for which to set the state.
	 * @param catchState The state to set for catchHandler.
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block). Will be updated with catchState.
	 * @param currentsNewCatchBlockStates The newly assigned catch block states. Will be updated with catchState.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 */
	private static void assignCatchState(CatchHandler catchHandler, int catchState, HashSet<Integer> knownStates,
			                             List<Integer> currentsNewCatchBlockStates, String prefix, Logger logger) {
		logger.log(Level.FINE, prefix+"Setting this catch block's state to " + catchState);
		catchHandler.setState(catchState);
		knownStates.add(catchState);		// <-- Ideally, the catch state is only added to knownStates after all current's catch blocks have been handled, because if there is another catch block (for the current try block) at the same level as the catch block we're looking at now, this should have the same state!
		currentsNewCatchBlockStates.add(catchState);
	}

	/**
	 * Checks that the given parent's state (if valid) matches the given targetToState. An invalid parent state is set to tryToState.
	 * 
	 * @param parent A parent TryBlock or CatchHandler.
	 * @param targetToState The state the parent should have. 
	 * @param knownStates The set of 'known' states (states already matched to a try or catch block). Will be updated when the parent state is set.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @throws InvalidDataTypeException If there is a state mismatch between the parent and the tryToState.
	 */
	private static void checkAndSetParentState(ITryCatch parent, Integer targetToState, HashSet<Integer> knownStates, String prefix, Logger logger) throws InvalidDataTypeException {
		if (parent == null) {
			logger.log(Level.FINE, prefix+"Parent is null so cannot do anything for it.");
			return;
		}

		if (parent.hasValidState()) {
			if (targetToState != parent.getState()) {
				var msg = "States do not match! toState " + targetToState + " != parent try state " + parent.getState();
				logger.log(Level.SEVERE, prefix+msg);
				throw new InvalidDataTypeException(msg);
			}
			else {
				logger.log(Level.FINE, prefix+"Parent's state matches the expected value.");
			}
		}
		else {
			logger.log(Level.FINE, prefix+"Setting parent state to " + targetToState);
			parent.setState(targetToState);
			knownStates.add(targetToState);
		}
	}

	/**
	 * Checks that the given parent's state is valid.
	 * 
	 * @param parent A parent TryBlock or CatchHandler.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 * @throws InvalidDataTypeException If there is a state mismatch between the parent and the tryToState.
	 */
	private static void checkParentState(ITryCatch parent, String prefix, Logger logger) throws InvalidDataTypeException {
		if (parent != null && !parent.hasValidState()) {
			var msg = "Expected to have a valid parent state by now!";
			logger.log(Level.SEVERE, prefix+msg);
			throw new InvalidDataTypeException(msg);
		}
	}

	/**
	 * Returns the 'from states' from the unwind map that have not yet been assigned to a try or catch block,
	 * that unwind to the given targetToState, and that are higher than a given value.
	 * 
	 * @param unwindMap An UnwindMap containing state transition information.
	 * @param knownStates The already-assigned states.
	 * @param targetToState The state a 'from state' should unwind to.
	 * @param cutoffFromState The value above which a 'from state' must be to qualify for inclusion.
	 * @return A list of 'from states' that have not yet been assigned to a try or catch block.
	 * @throws InvalidDataTypeException If there is a problem accessing the unwind map.
	 */
	private static List<Integer> filterFromStates(UnwindMap unwindMap, HashSet<Integer> knownStates, Integer targetToState, Integer cutoffFromState) throws InvalidDataTypeException {
		var allNotYetKnownFromStates = new ArrayList<Integer>();
		var nrUnwindMapEntries = unwindMap.getCount();
		for (var unwindOrdinal = 0; unwindOrdinal < nrUnwindMapEntries; unwindOrdinal++) {
			var toState = unwindMap.getToState(unwindOrdinal);
			if (knownStates.contains(unwindOrdinal) || unwindOrdinal <= cutoffFromState)
				continue;
			if (toState != targetToState)
				continue;
			allNotYetKnownFromStates.add(unwindOrdinal);
		}
		return allNotYetKnownFromStates;
	}

	/**
	 * Logs debugging information about the known states and the possible catch block states.
	 * 
	 * @param knownStates The already-assigned states.
	 * @param allNotYetKnownFromStates The possible catch block states.
	 * @param prefix A string prefix used for logging to indicate the level of recursion (depth).
	 * @param logger The logger to use.
	 */
	private static void logStates(HashSet<Integer> knownStates, List<Integer> allNotYetKnownFromStates, String prefix,
			Logger logger) {
		logStatesLine(knownStates, prefix+"- Known states: ", Level.FINE, logger);
		logStatesLine(allNotYetKnownFromStates, prefix+"- Possible catch states: ", Level.FINE, logger);
	}

	/**
	 * Logs a line showing all states in the given collection.
	 * 
	 * @param states The collection of states to be logged. 
	 * @param prefix The line prefix.
	 * @param logLevel The log level to use.
	 * @param logger The logger to use.
	 */
	private static void logStatesLine(Collection<Integer> states, String prefix, Level logLevel, Logger logger) {
		var strStates = new StringBuilder(prefix);
		for (var state : states) {
			strStates.append(state).append(",");
		}
		// Clean up the output; make sure there is no trailing comma.
		if (strStates.length() > 0) {
			strStates.deleteCharAt(strStates.length() - 1);
		}			
		logger.log(logLevel, strStates.toString());
	}

}
