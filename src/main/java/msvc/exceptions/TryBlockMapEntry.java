package msvc.exceptions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import ghidra.program.model.address.Address;

/**
 * Represents a TryBlockmapEntry, as implemented by MSVC.
 */
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
	
	/**
     * Creates a TryBlockMapEntry.
     *
     * @param mapIndex The index of this entry in the TryBlockMap.
     * @param tryLow The tryLow value.
     * @param tryHigh The tryHigh value.
     * @param catchHigh The catchHigh value.
     * @param nCatches The nCatches value.
     */
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

	/**
     * Creates a TryBlockMapEntry.
     *
     * @param mapIndex The index of this entry in the TryBlockMap.
     * @param tryLow The tryLow value.
     * @param tryHigh The tryHigh value.
     * @param catchHigh The catchHigh value.
     * @param nCatches The nCatches value.
     * @param pHandlerArray The address of the HandlerArray data structure containing the catch block data.
     * @param tryBlock The TryBlock associated with this TryBlockMapEntry.
     * @param catchHandlers The list of CatchHandlers associated with this TryBlockMapEntry.
     */
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

	/**
	 * Sets tryBlock as the try block for this TryBlockMapEntry.
	 * @param tryBlock The TryBlock to set as the try block for this TryBlockMapEntry.
	 */
	public void setTryBlock(TryBlock tryBlock ) {
		this.tryBlock = tryBlock;
	}

	/**
     * Adds a catch handler to this TryBlockMapEntry.
     * @param catchHandler The catch handler to add.
     */
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
	 * Determines if this TryBlockMapEntry is a 'leaf', meaning that is has no nested try/catch blocks anywhere.
	 * @return true if this structure can be called a leaf, false if not.
	 */
	public boolean isLeaf() {
		return !nestingInTry() && !nestingInCatches();
	}

	/**
	 * Determines if this TryBlockMapEntry can be called a 'singlet leaf' (a leaf with only one catch block).
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
	
	/**
     * Retrieves the TryBlockMapEntries nested within the try block associated with this TryBlockMapEntry.
     * @return The list of TryBlockMapEntries nested in the try block.
     */
	public List<TryBlockMapEntry> getNestedInTry() {
		return tryBlock.getNested();
	}

    /**
     * Retrieves the list of TryBlockMapEntries that are known to be nested in catch handler (catch blocks),
     * but for which the correct catch handlers are not yet known.
     * 
     * @return The list of TryBlockMapEntries pending to be nested in the correct catch blocks.
     */
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
	
    /**
     * Nests a TryBlockMapEntry in the try block associated with the current TryBlockMapEntry.
     * Note that this method is intended for constructing based on existing structures and not
     * for constructing new structures from scratch; hence, value like tryHigh will not be updated!
     * 
     * @param tryBlockMapEntry The TryBlockMapEntry to nest in the try block.
     */
	public void nestInTry(TryBlockMapEntry tryBlockMapEntry) {
		tryBlock.nest(tryBlockMapEntry);
	}
	
	/**
     * Nests a TryBlockMapEntry within the catch handler(s) associated with the current TryBlockMapEntry.
     * If there is a single catch handler, the TryBlockMapEntry will be nested in that handler;
     * if there are multiple catch handlers, The TryBlockMapEntry will be accepted, but the
     * correct handler will have to be determined later.
     * Note that this method is intended for constructing based on existing structures and not
     * for constructing new structures from scratch; hence, value like catchHigh will not be updated!
     * 
     * @param tryBlockMapEntry The TryBlockMapEntry to nest in a catch handler.
     */
	public void nestInCatches(TryBlockMapEntry tryBlockMapEntry) {
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

	
	/**
     * Returns the TryBlock associated with this TryBlockMapEntry.
     * @return The TryBlock associated with this TryBlockMapEntry.
     */
	public TryBlock getTryBlock() {
		return tryBlock;
	}
	
    /**
     * Returns the list of CatchHandlers associated with this TryBlockMapEntry.
     * @return The list of CatchHandlers associated with this TryBlockMapEntry.
     */
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

    /**
     * Provides a header line with a description of this TryBlockMapEntry.
     * @return A string containing a single-line description of the properties of this TryBlockMapEntry.
     */
	public String getHeaderInfoLine() {
		return String.format("TryBlockMapEntry [%d]\t%d-%d,%d,%d", mapIndex, tryLow, tryHigh, catchHigh, nCatches);
	}

    /**
     * Describes the (possibly nested) layout of this TryBlockMapEntry.
     *
     * @return A list of strings describing the (possibly nested) layout of this TryBlockMapEntry.
     */
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
