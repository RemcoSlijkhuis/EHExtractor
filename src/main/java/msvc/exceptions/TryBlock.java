package msvc.exceptions;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a try block as implemented by MSVC.
 */
public class TryBlock implements ITryCatch { 

	private int tryLow;
	private int tryHigh;  // This should really be determined dynamically, based on TryBlockMapEntries nested in this try block.

	private List<TryBlockMapEntry> nested = null;

	/**
     * Constructs a TryBlock with the specified tryLow and tryHigh values.
     *
     * @param tryLow The tryLow value.
     * @param tryHigh The tryHigh value.
     */
	public TryBlock(int tryLow, int tryHigh) {
		this.tryLow = tryLow;
		this.tryHigh = tryHigh;

		nested = new ArrayList<TryBlockMapEntry>();
	}
	
	/**
     * Identifies this object as a try block.
     *
     * @return BlockType.TRY.
     */
	public BlockType getBlockType() {
		return BlockType.TRY;
	}

	public int getTryLow() {
		return tryLow;
	}

	public int getTryHigh() {
		return tryHigh;
	}
	
	/**
	 * Returns this try block's state, which is represented by the tryLow value.
     *
     * @return This try block's state value.
	 */
	public int getState() {
		return tryLow;
	}

	/**
     * 'Sets' the state of this try block. Not to be used when constructing a try block; just set the right tryLow and tryHigh values through the constructor
     * 
     * <p>This function is called as part of determining the try/catch block layout of a function, and for a try block serves as a double-check that the correct state value has been determined.
     *
     * @param state The state to set.
     * @throws IllegalArgumentException if state does not match tryLow.
     */
	public void setState(int state) {		
		if (state != tryLow)
			throw new IllegalArgumentException("A try block's state must equal its tryLow value.");
	}

	/**
     * Checks if this try block's state is valid (>= -1).
     *
     * @return true if the state is valid, false otherwise.
     */
	public boolean hasValidState() {
		return this.tryLow >= -1;
	}

    /**
     * Adds a nested TryBlockMapEntry to this try block.
     *
     * @param tryBlockMapEntry The TryBlockMapEntry to nest.
     */
	public void nest(TryBlockMapEntry tryBlockMapEntry) {
		nested.add(tryBlockMapEntry);
	}

    /**
     * Retrieves all nested TryBlockMapEntries.
     *
     * @return The list of nested TryBlockMapEntries.
     */
	public List<TryBlockMapEntry> getNested() {
		return nested;
	}

    /**
     * Describes the (possibly nested) layout of this try block.
     *
     * @return A list of strings describing the (possibly nested) layout of this try block.
     */
	public List<String> getNestingInfoLines() {
		List<String> lines = new ArrayList<String>();

		// Try block info line.
		var line = String.format("Try (state=%d)", tryLow);

		// Anything nested in the try block?
		if (nested.size() == 0) {
			line += " {}";
			lines.add(line);
		}
		else {
			line += " {";
			lines.add(line);
			for (var nestedTryBlockMapEntry : nested) {
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
