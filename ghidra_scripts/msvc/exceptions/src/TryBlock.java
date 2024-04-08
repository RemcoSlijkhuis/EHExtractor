package msvc.exceptions.src;

import java.util.ArrayList;
import java.util.List;

public class TryBlock implements ITryCatch { 

	private int tryLow;
	private int tryHigh;  // This should really be determined dynamically, based on TryBlockMapEntries nested in this try block.

	private List<TryBlockMapEntry> nested = null;

	public TryBlock(int tryLow, int tryHigh) {
		this.tryLow = tryLow;
		this.tryHigh = tryHigh;

		nested = new ArrayList<TryBlockMapEntry>();
	}
	
	// ITryCatch implementations.
	public BlockType getBlockType() {
		return BlockType.TRY;
	}

	public int getTryLow() {
		return tryLow;
	}

	public int getTryHigh() {
		return tryHigh;
	}
	
	public int getState() {
		return tryLow;
	}

	public void setState(int state) {		
		if (state != tryLow)
			throw new IllegalArgumentException("A try block's state must equal its tryLow value.");
	}

	public boolean hasValidState() {
		return this.tryLow >= -1;
	}

	public void nest(TryBlockMapEntry tryBlockMapEntry) {
		nested.add(tryBlockMapEntry);
	}

	//
	public List<TryBlockMapEntry> getNested() {
		return nested;
	}

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
