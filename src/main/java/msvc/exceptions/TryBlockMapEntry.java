package msvc.exceptions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerModel;
import ghidra.app.cmd.data.exceptionhandling.EHTryBlockModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;

public class TryBlockMapEntry {
	private int mapIndex = 0;

	private int tryLow = 0;
	private int tryHigh = 0;
	private int catchHigh = 0;
	private int nCatches = 0;
	private Address pHandlerArray = null;

	private TryBlock tryBlock = null;
	private List<CatchHandler> catchHandlers = null;
	private List<TryBlockMapEntry> toBeNestedInCatches = null;
	
	public TryBlockMapEntry(int mapIndex, int tryLow, int tryHigh, int catchHigh, int nCatches) {
		this.mapIndex = mapIndex;
		this.tryLow = tryLow;
		this.tryHigh = tryHigh;
		this.catchHigh = catchHigh;
		this.nCatches = nCatches;
		this.pHandlerArray = null;
		
		this.tryBlock = null;
		this.catchHandlers = new ArrayList<CatchHandler>();	
		this.toBeNestedInCatches = new ArrayList<TryBlockMapEntry>();
	}

	public TryBlockMapEntry(int mapIndex, int tryLow, int tryHigh, int catchHigh, int nCatches, Address pHandlerArray, TryBlock tryBlock, List<CatchHandler> catchHandlers) {
		this.mapIndex = mapIndex;
		this.tryLow = tryLow;
		this.tryHigh = tryHigh;
		this.catchHigh = catchHigh;
		this.nCatches = nCatches;
		this.pHandlerArray = pHandlerArray;
		
		this.tryBlock = tryBlock;		
		this.catchHandlers = catchHandlers;
		this.toBeNestedInCatches = new ArrayList<TryBlockMapEntry>();
	}

	public void setTryBlock(TryBlock tryBlock ) {
		this.tryBlock = tryBlock;
	}

	public void addCatchHandler(CatchHandler catchHandler) {
		this.catchHandlers.add(catchHandler);
	}
	
	/**
	 * Returns whether or not there are nested try/catch blocks in the try block.
	 * @return true if there are, false if not.
	 */
	public boolean nestingInTry() {
		return tryLow != tryHigh;
	}
	
	/**
	 * Returns whether or not there are any nested try/catch blocks in any of the catch blocks.
	 * @return true if there are, false if not.
	 */
	public boolean nestingInCatches() {
		return catchHigh != tryHigh+1;
	}

	/**
	 * @return true if this structure can be called a leaf, false if not.
	 */
	public boolean isLeaf() {
		return !nestingInTry() && !nestingInCatches();
	}

	/**
	 * @return true if this structure can be called a singlet leaf, false if not.
	 */
	public boolean isSingletLeaf() {
		return isLeaf() && nCatches == 1;
	}

	public Range<Integer> getStateRange() {
		return new Range<Integer>(tryLow, Math.max(tryHigh, catchHigh));
	}

	public Range<Integer> getTryStateRange() {
		return new Range<Integer>(tryLow, tryHigh);
	}
	
	
	public List<TryBlockMapEntry> getNestedInTry() {
		return tryBlock.getNested();
	}

	public List<TryBlockMapEntry> getNestedInCatches() {
		List<TryBlockMapEntry> nested = new ArrayList<TryBlockMapEntry>(); 

		var uniqueEntries = new HashSet<TryBlockMapEntry>();	// TODO This will only give unique TryBlockMapEntries when I add overrides for Equals and getHashCode...
		for (var catchHandler : catchHandlers) {
			uniqueEntries.addAll(catchHandler.getNested());
		}
		nested.addAll(uniqueEntries);

		return nested;
	}

	public List<TryBlockMapEntry> getToBeNestedInCatches() {
		return toBeNestedInCatches;
	}
	
	public void nestInTry(TryBlockMapEntry tryBlockMapEntry) {
		tryBlock.nest(tryBlockMapEntry);
	}
	
	public void nestInCatches(TryBlockMapEntry tryBlockMapEntry) {
		/* Previous approach.
		// Note: This will add the tryBlockMapEntry to all catch blocks.
		for (var catchHandler : catchHandlers) {
			catchHandler.nest(tryBlockMapEntry);
		}
		*/

		// Note: Catch handlers should only be added when instantiating TryBlockMapEntry.
		if (catchHandlers.size() == 1) {
			// There is only one catch handler, so nest the TryBlockMapEntry in it.
			catchHandlers.get(0).nest(tryBlockMapEntry);
		}
		else if (catchHandlers.size() > 1) {
			// There are multiple catch handlers; when this method is used to nest something in a catch,
			// we have no way of knowing which catch is the right one. We will have to figure that out
			// later when scanning through the compiled function code.
			toBeNestedInCatches.add(tryBlockMapEntry);
		}		
	}

	
	public TryBlock getTryBlock() {
		return tryBlock;
	}
	
	public List<CatchHandler> getCatchHandlers() {
		// To make sure no catch handlers are added or removed; modifying a catch handler itself is ok.
		return Collections.unmodifiableList(catchHandlers);
	}
	
	
	public int getMapIndex() {
		return mapIndex;
	}

	public int getTryLow() {
		return tryLow;
	}

	public int getTryHigh() {
		return tryHigh;
	}

	public int getCatchHigh() {
		return catchHigh;
	}
	
	public int getNCatches() {
		return nCatches;
	}

	public String getHeaderInfoLine() {
		return String.format("TryBlockMapEntry [%d]\t%d-%d,%d,%d", mapIndex, tryLow, tryHigh, catchHigh, nCatches);
	}

	public List<String> getInfoLines() {
		List<String> lines = new ArrayList<String>();

		lines.add("tryLow: " + tryLow);
		lines.add("tryHigh: " + tryHigh);
		lines.add("catchHigh: " + catchHigh);
		lines.add("nCatches: " + nCatches);
		lines.add("pHandlerArray: " + pHandlerArray);

		for (int i = 0; i < catchHandlers.size(); i++) {
			lines.add("CatchHandler " + i + ":");
			var chLines = catchHandlers.get(i).getInfoLines();
			for (var chLine : chLines) {
				lines.add("  " + chLine);
			}			
		}
		return lines;
	}

	public List<String> getNestingInfoLines() {
		List<String> lines = new ArrayList<String>();
		
		// TryBlockMapEntry info line.
		var line = "/* " + getHeaderInfoLine() + " */";
		lines.add(line);
		
		// Try block info line(s).
		var tryLines = tryBlock.getNestingInfoLines();
		for (var tryLine : tryLines) {
			lines.add(tryLine);
		}

		// Catch block info line(s).
		for (var catchHandler : catchHandlers) {
			var catchLines = catchHandler.getNestingInfoLines();
			for (var catchLine : catchLines) {
				lines.add(catchLine);
			}
		}
		
		// 'To be nested in catches' info lines, if there is anything.		
		if (toBeNestedInCatches.size() > 0) {
			line = "ToBeNestedInCatches {";
			lines.add(line);
			for (var nestedTryBlockMapEntry : toBeNestedInCatches) {
				var nestedLines = nestedTryBlockMapEntry.getNestingInfoLines();
				for (var nestedLine : nestedLines) {
					lines.add("  " + nestedLine);
				}
			}
			line = "}";
			lines.add(line);
		}

		return lines;
	}

}
