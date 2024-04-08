package msvc.exceptions.src;

import ghidra.program.model.data.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

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

	public void analyze() throws InvalidDataTypeException {
		if (tryBlockMapEntries == null) {
			logger.log(Level.INFO, "No TryBlockMapEntries to analyze.");
			return;
		}

		/* Determine the layout of the try/catch blocks as much as possible just from the data structures. */
		ArrayList<TryBlockMapEntry> outerTryBlockMapEntries = determineLayout(tryBlockMapEntries);

		// Show what we now know about the try/catch block structures.
		displayTryCatchBlockOverview(outerTryBlockMapEntries, "Try/catch block overview, after determineLayout but without unwind information applied:");

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
			logger.log(Level.INFO, "No unwind information to apply.");
			return;
		}

		logger.log(Level.INFO, "Applying unwind information.");
		for (int i=0; i<unwindMap.getCount(); i++) {
			logger.log(Level.FINE, "From " + i + " to " + unwindMap.getToState(i));
		}

		HashSet<Integer> knownStates = new HashSet<Integer>();
		for (var outer : outerTryBlockMapEntries) {
			recurse(outer, null, knownStates, unwindMap, "");
		}
		
		//...
		displayTryCatchBlockOverview(outerTryBlockMapEntries, "Try/catch block overview:");
	}
	
	private void displayTryCatchBlockOverview(List<TryBlockMapEntry> outerTryBlockMapEntries, String header) {
		List<String> lines = getTryCatchBlockOverview(outerTryBlockMapEntries, header);
		for (String line : lines) {
			logger.log(Level.INFO, line);
		}
	}

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
	 *  Determine the layout of the try/catch blocks as much as possible just 'from the data structures'.
	 * @param tryBlockMapEntries
	 * @return
	 */
	public static ArrayList<TryBlockMapEntry> determineLayout(List<TryBlockMapEntry> tryBlockMapEntries) {
		Logger.getLogger("EHExtractor").log(Level.FINE, "Let's try to look for nested try/catch blocks using the contents of the TryBlockMapEntry array.");

		// Sort the tryBlockMapEntries in DESCENDING order of their tryLow value.
		var tryLowComparator =  new TryLowComparator();
		Collections.sort(tryBlockMapEntries, tryLowComparator.reversed());

		var todo = new ArrayList<TryBlockMapEntry>();

		for (var tryBlockMapEntry : tryBlockMapEntries) {
			var tryHigh = tryBlockMapEntry.getTryHigh();
			var catchHigh = tryBlockMapEntry.getCatchHigh();
			
			var nestingInTry = tryBlockMapEntry.nestingInTry();				
			var nestingInCatches = tryBlockMapEntry.nestingInCatches();
			var isLeaf = tryBlockMapEntry.isLeaf();
			var isSingletLeaf = tryBlockMapEntry.isSingletLeaf();
			
			// TODO Make unit tests for this!

			// If this is a leaf, it can only be nested itself inside another try or catch block we haven't encountered yet: put it on the todo list.
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
	
	/*
	private void recurse(TryBlockMapEntry current, ITryCatch parent, HashSet<Integer> knownStates, EHUnwindModel unwindModel, String prefix) throws InvalidDataTypeException {
		// This is the main 'recurse' entry point; it converts the EHUnwindModel to a proper UnwindMap object.
	
		// If I want to write tests for the 'recurse' method, I need to be able to construct unwind map information myself.
		// To instantiate the EHUnwindModel class a full binary program needs to be present; this is not practical.
		// Therefore, instead of passing unwindMap to 'recurse', let's create a replacement object containing the same information,
		// but which can be created more easily.
		var unwindMap = UnwindMapFactory.getUnwindMap(unwindModel);
		
		for (int i=0; i<unwindMap.getCount(); i++) {
			logger.log(Level.FINE, "From " + i + " to " + unwindMap.getToState(i));
		}

		recurse(current, parent, knownStates, unwindMap, prefix);
	}
	*/

	public static void recurse(TryBlockMapEntry current, ITryCatch parent, HashSet<Integer> knownStates, UnwindMap unwindMap, String prefix) throws InvalidDataTypeException {
		var logger = Logger.getLogger("EHExtractor");

		// Display some debugging info.
		logger.log(Level.FINE, prefix+"Current: " + current.getHeaderInfoLine());
		logger.log(Level.FINE, prefix+"Nesting in try: " + current.nestingInTry());
		logger.log(Level.FINE, prefix+"Nesting in catches: " + current.nestingInCatches());
		if (parent != null) {
			logger.log(Level.FINE, prefix+"Parent is a " + parent.getBlockType());
		}
		else {
			logger.log(Level.FINE, prefix+"Parent is null.");
		}

		// This function is about applying unwind information, so if we don't have it, there's nothing to do.
		if (unwindMap == null || unwindMap.getCount() == 0) {
			logger.log(Level.FINE, prefix+"No unwind map information; nothing to do.");
			return;
		}
		

		logger.log(Level.FINE, prefix+"Looking at current's try block. State is " + current.getTryLow());
		
		// TODO Hm #2... Should make this depth-first.				
		if (current.nestingInTry()) {
			logger.log(Level.FINE, prefix+"Going into try/catches nested in current's try block.");
			// We need to have the states of all try blocks that are direct descendants of the current try block
			// in order to assign the proper states to their catch blocks.
			for (var child : current.getNestedInTry()) {
				knownStates.add(child.getTryLow());
			}
			for (var child : current.getNestedInTry()) {
				recurse(child, current.getTryBlock(), knownStates, unwindMap, prefix+"  ");
			}
		}

		// Now handle the current try.
		logger.log(Level.FINE, prefix+"Handling current's try block.");
		// Get the state of the try block for the current/child TryBlockMapEntry and
		// look up the state to which it will unwind; it should match the state of the parent.
		var tryState = current.getTryBlock().getState();  //current.getTryLow();
		var tryToState = unwindMap.getToState(tryState);
		logger.log(Level.FINE, prefix+"Current try state "+tryState+" unwinds to toState "+tryToState);
		knownStates.add(tryState);
			
		if (parent != null) {
			if (parent.hasValidState()) {
				if (tryToState != parent.getState()) {
					var msg = "States do not match! toState " + tryToState + " != parent try state " + parent.getState();
					logger.log(Level.SEVERE, prefix+msg);
					throw new InvalidDataTypeException(msg);
				}
				else {
					logger.log(Level.FINE, prefix+"Parent's state matches the expected value.");
				}
			}
			else {
				logger.log(Level.FINE, prefix+"Setting parent state to " + tryToState);
				parent.setState(tryToState);
				knownStates.add(tryToState);
			}
		}
		else {
			logger.log(Level.FINE, prefix+"Parent is null so cannot do anything for it.");
		}
		// TODO Can I know anything about what a valid parent state would be?

		// Now it's catch block handling time.

		// First handle anything that is nested in this TryBlockMapEntry's catch blocks. 
		if (current.nestingInCatches()) {
			logger.log(Level.FINE, prefix+"Going into try/catches nested in current's catch blocks.");
			// Things can already be nested in specific catch handlers.
			for (var catchHandler : current.getCatchHandlers()) {
				for (var child : catchHandler.getNested()) {
					recurse(child, catchHandler, knownStates, unwindMap, prefix+"  ");
				}
			}
			// For other things, we may know that they are nested in some catch handler(s), but we
			// don't know in which.
			for (var child : current.getToBeNestedInCatches()) {
				// TODO The parent is null here, which may pose problems in some cases; I think...
				recurse(child, null, knownStates, unwindMap, prefix+"  ");
			}
		}
		
		// Now handle the current TryBlockMapEntry's catches.
		logger.log(Level.FINE, prefix+"Handling current's catch blocks.");
		// I should have a valid parent state (if I have a parent) because we handled the try block first.
		// TODO "because we handled the try block first"... does that make sense?

		if (parent != null && !parent.hasValidState()) {
			var msg = "Expected to have a valid parent state by now!";
			logger.log(Level.SEVERE, prefix+msg);
			throw new InvalidDataTypeException(msg);
		}

		int targetToState = -100;
		if (parent != null) {
			targetToState = parent.getState(); // Checked while handling the try block to which this catch block belongs.
		}
		else {
			targetToState = tryToState;
		}
		logger.log(Level.FINE, prefix + "targetToState determined to be " + targetToState);
		
		if (true || parent != null) {

			//var targetToState = parent.getState(); // Checked while handling the try block to which this catch block belongs.

			List<Integer> currentsNewCatchBlockStates = new ArrayList<Integer>();

			for (var catchHandler : current.getCatchHandlers()) {
				// If we already know this catch block's state there is no need to do anything.
				if (catchHandler.hasValidState()) {
					logger.log(Level.FINE, prefix+"State already determined for this catch block (it's "+catchHandler.getState()+").");
					continue;
				}
				
				// Get the list of all 'from' states that have not been assigned to a try or catch block yet.
				// One of these must be the one for this catch block.
				var allNotYetKnownFromStates = new ArrayList<Integer>();
				var nrUnwindMapEntries = unwindMap.getCount();
				for (var unwindOrdinal = 0; unwindOrdinal < nrUnwindMapEntries; unwindOrdinal++) {
					if (knownStates.contains(unwindOrdinal))  // && !currentsCatchBlockStates.contains(unwindOrdinal))
						continue;
					var toState = unwindMap.getToState(unwindOrdinal);
					if (toState != targetToState)
						continue;
					allNotYetKnownFromStates.add(unwindOrdinal);
				}

				// Now determine the state of the current catch block.
				logger.log(Level.FINE, prefix+String.format("- Current try state: %d", current.getTryLow()));

				var strTryStates = prefix+"- Known (try?) states: ";
				for (var knownState : knownStates) {
					strTryStates += knownState + ",";
				}
				logger.log(Level.FINE, strTryStates);

				var strCatchStates = prefix+"- Possible catch states: ";
				for (var i=0; i<allNotYetKnownFromStates.size(); i++) {
					strCatchStates += allNotYetKnownFromStates.get(i) + ",";
				}
				logger.log(Level.FINE, strCatchStates);
				
				if (allNotYetKnownFromStates.size() == 0 && currentsNewCatchBlockStates.size() == 0) {
					var msg = "Did not find any possible states for catch blocks!";
					logger.log(Level.SEVERE, prefix+msg);
					throw new InvalidDataTypeException(msg);
				}
				else if (allNotYetKnownFromStates.size() == 0 && currentsNewCatchBlockStates.size() == 1) {
					logger.log(Level.FINE, prefix+"No new state available but we found one state for an earlier catch block at this level; going to use that.");
					var catchState = currentsNewCatchBlockStates.get(0);
					logger.log(Level.FINE, prefix+"Setting this catch block's state to " + catchState);
					catchHandler.setState(catchState);
					continue;
				}
				else if (allNotYetKnownFromStates.size() > 1) {
					var msg = "Found multiple possible states for catch blocks, trying to limit them.";
					logger.log(Level.FINE, prefix+msg);
					var tempStates = new ArrayList<Integer>();
					for (var tempState : allNotYetKnownFromStates) {
						if (tempState > current.getTryLow()) {
							tempStates.add(tempState);
						}
					}
					allNotYetKnownFromStates = tempStates;
				}

				if (allNotYetKnownFromStates.size() == 0) {
					var msg = "Did not find any possible states for catch blocks with a value higher than the try block!";
					logger.log(Level.SEVERE, prefix+msg);
					throw new InvalidDataTypeException(msg);
				}
				else if (allNotYetKnownFromStates.size() == 1) {
					logger.log(Level.FINE, prefix+"Found one state for the catch block(s)!");
					var catchState = allNotYetKnownFromStates.get(0);
					logger.log(Level.FINE, prefix+"Setting this catch block's state to " + catchState);
					catchHandler.setState(catchState);
					knownStates.add(catchState);		// <-- Wrong: the catch state should only be added to knownStates after all current's catch blocks have been handled, because if there is another catch block (for the current try block) at the same level as the catch block we're looking at now, this should have the same state!
					currentsNewCatchBlockStates.add(catchState);
				}
				else if (allNotYetKnownFromStates.size() == 0 && currentsNewCatchBlockStates.size() == 1) {
					logger.log(Level.FINE, prefix+"No new state available but we found one state for an earlier catch block at this level; going to use that.");
					var catchState = currentsNewCatchBlockStates.get(0);
					logger.log(Level.FINE, prefix+"Setting this catch block's state to " + catchState);
					catchHandler.setState(catchState);
				}
				else {
					var msg = "Still have multiple possible states for catch blocks! Doing some more checking.";
					logger.log(Level.FINE, prefix+msg);
					
					// It can be really simple...
					if (current.getTryLow() == current.getTryHigh() && current.getCatchHigh() == current.getTryHigh()+1) {
						var catchState = current.getTryHigh()+1;
						if (allNotYetKnownFromStates.contains(catchState)) {
							logger.log(Level.FINE, prefix+"Setting this catch block's state to " + catchState);
							catchHandler.setState(catchState);
							knownStates.add(catchState);		// <-- Wrong: the catch state should only be added to knownStates after all current's catch blocks have been handled, because if there is another catch block (for the current try block) at the same level as the catch block we're looking at now, this should have the same state!
							currentsNewCatchBlockStates.add(catchState);
							continue;
						}
					}					
					
					msg = "No, cannot determine the catch block state!";
					throw new InvalidDataTypeException(msg);
				}
				
			}
		}
		else {
			logger.log(Level.FINE, prefix+"Parent is null so cannot do anything for it.");
		}
		// TODO Can I know anything about what a valid parent state would be?
		
	}

	public List<String> getInfoLines() {
		List<String> lines = new ArrayList<String>();
		
		lines.add("magicNumber: " + String.format("%08x", magicNumber));
		lines.add("bbtFlags: " + String.format("%3s", Integer.toBinaryString(bbtFlags)).replace(' ', '0'));
		lines.add("maxState: " + maxState);
		lines.add("pUnwindMap: " + pUnwindMap);
		lines.add("nTryBlocks: " + nTryBlocks);
		lines.add("pTryBlockMap: " + pTryBlockMap);
		lines.add("nIPMapEntries: " + nIPMapEntries);
		lines.add("pIPToStateMap: " + pIPToStateMap);
		lines.add("pESTypeList: " + pESTypeList);
		lines.add("ehFlags: " + String.format("%08x", ehFlags));

		if (tryBlockMapEntries != null) {
			for (int i = 0; i < tryBlockMapEntries.size(); i++) {
				lines.add("  TryBlockMapENtry " + i + ":");
				var tbmeLines = tryBlockMapEntries.get(i).getInfoLines();
				for (var tbmeLine : tbmeLines) {
					lines.add("  " + tbmeLine);
				}			
			}
	
		}

		return lines;
	}

}
