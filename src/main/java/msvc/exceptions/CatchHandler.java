package msvc.exceptions;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerTypeModifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.scalar.Scalar;

/**
 * Represents a catch block as implemented by MSVC.
 */
public class CatchHandler implements ITryCatch {

	private EHCatchHandlerTypeModifier adjectives = null;
	private Address pType = null;
	private Scalar dispCatchObj = null;
	private Address address = null;
	private TypeDescriptorModel typeDescriptor = null;
	private String typeName = null; 
	private String handlerName = null;
	
	private int state = -2;	// TODO make state an Integer so it can be null
	private Integer addressInt = 0;

	private List<TryBlockMapEntry> nested = null;
	
	/**
     * Creates a CatchHandler object (catch block).
     * @param adjectives Modifier flags (not really used).
     * @param pType Address of an RTTI descriptor of the exception type (not really used).
     * @param dispCatchObj "Displacement of catch object from base" (not really used).
     * @param address Address where the code for the catch block starts.
     * @param typeDescriptor The type descriptor model for the exception handled by this catch block.
     * @param handlerName The name of the function with the catch block code, as seen by Ghidra.
     */
	public CatchHandler(EHCatchHandlerTypeModifier adjectives, Address pType, Scalar dispCatchObj, Address address, TypeDescriptorModel typeDescriptor, String handlerName) {
		this.adjectives = adjectives;
		this.pType = pType;
		this.dispCatchObj = dispCatchObj;
		this.address = address;
		this.addressInt = 0;
		this.typeDescriptor = typeDescriptor;
		this.handlerName = handlerName;

		if (typeDescriptor != null) {
			typeName = typeDescriptor.getDescriptorTypeNamespace();
		}
		else {
			typeName = "...";
		}

		this.nested = new ArrayList<TryBlockMapEntry>();
	}

	/**
     * Creates a CatchHandler object (catch block).
     * @param adjectives Modifier flags (not really used).
     * @param pType Address of an RTTI descriptor of the exception type (not really used).
     * @param dispCatchObj "Displacement of catch object from base" (not really used).
     * @param address Address where the code for the catch block starts.
     * @param typeDescriptor The type descriptor model for the exception handled by this catch block.
     * @param handlerName The name of the function with the catch block code, as seen by Ghidra.
     */
	public CatchHandler(EHCatchHandlerTypeModifier adjectives, Address pType, Scalar dispCatchObj, Integer address, TypeDescriptorModel typeDescriptor, String handlerName) {
		this.adjectives = adjectives;
		this.pType = pType;
		this.dispCatchObj = dispCatchObj;
		this.address = null;
		this.addressInt = address;
		this.typeDescriptor = typeDescriptor;
		this.handlerName = handlerName;

		if (typeDescriptor != null) {
			typeName = typeDescriptor.getDescriptorTypeNamespace();
		}
		else {
			typeName = "...";
		}

		this.nested = new ArrayList<TryBlockMapEntry>();
	}

	/**
     * Creates a CatchHandler object (catch block).
     * @param adjectives Modifier flags (not really used).
     * @param pType Address of an RTTI descriptor of the exception type (not really used).
     * @param dispCatchObj "Displacement of catch object from base" (not really used).
     * @param altParams Class with the other relevant (and most useful) catch block properties.
     * @param handlerName The name of the function with the catch block code, as seen by Ghidra.
     */
	public CatchHandler(EHCatchHandlerTypeModifier adjectives, Address pType, Scalar dispCatchObj, AlternativeParams altParams, String handlerName) {
		this.adjectives = adjectives;
		this.pType = pType;
		this.dispCatchObj = dispCatchObj;
		this.address = altParams.address;
		this.addressInt = altParams.addressInt;
		this.typeDescriptor = altParams.typeDescriptor;
		this.typeName = altParams.typeName;
		this.handlerName = handlerName;

		if (typeDescriptor != null) {
			typeName = typeDescriptor.getDescriptorTypeNamespace();
		}
		else if (typeName == null || typeName.trim().equals("")) {
			typeName = "...";
		}

		this.nested = new ArrayList<TryBlockMapEntry>();
	}

	/**
	 * Helper class for setting several (most useful) parameters for CatchHandler construction. Uses the Builder pattern without .build().
	 */
	public static class AlternativeParams {
		private Address address;
		private Integer addressInt;

		TypeDescriptorModel typeDescriptor;
		String typeName;
		
		public AlternativeParams withAddress(Address address) {
			this.address = address;
			return this;
		}

		public AlternativeParams withAddress(Integer address) {
			this.addressInt = address;
			return this;
		}

		public AlternativeParams withExceptionType(TypeDescriptorModel typeDescriptor) {
			this.typeDescriptor = typeDescriptor;
			return this;
		}

		public AlternativeParams withExceptionType(String typeName) {
			this.typeName = typeName;
			return this;
		}
	}

	/**
     * Identifies this object as a catch block.
     *
     * @return BlockType.CATCH.
     */
	public BlockType getBlockType() {
		return BlockType.CATCH;
	}

	/**
	 * Returns this catch block's state value.
     *
     * @return This catch block's state value.
	 */
	public int getState() {
		return state;
	}

	/**
     * Sets the state of this catch block. Checks that it is not &lt; 1.
     *
     * @param state The state to set.
     * @throws IllegalArgumentException if state &lt; 1.
     */
	public void setState(int state) {
		if (state < -1)
			throw new IllegalArgumentException("A catch block's state cannot be < -1.");
		this.state = state;
	}

	/**
     * Sets the state of this catch block. Checks that it is not &lt; 1. Allows null as the only way to set the state to'undefined' (-2).
     *
     * @param state The state to set.
     * @throws IllegalArgumentException if state &lt; 1.
     */
	public void setState(Integer state) {
		if (state == null) {
			// Special case.
			this.state = -2;
			return;			
		}
		if (state < -1)
			throw new IllegalArgumentException("A catch block's state cannot be < -1.");
		this.state = state;
	}

	/**
     * Checks if this catch block's state is valid (>= -1).
     *
     * @return true if the state is valid, false otherwise.
     */
	public boolean hasValidState() {
		return state >= -1;
	}

    /**
     * Adds a nested TryBlockMapEntry to this catch block.
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

	
	public Address getAddress() {
		return address;
	}

	public String getAddressString() {
		if (address != null)
			return address.toString();
		return String.format("%08x", addressInt);
	}

	public String getTypeName() {
		return typeName;
	}
	
    /**
     * Describes the (possibly nested) layout of this catch block.
     *
     * @return A list of strings describing the (possibly nested) layout of this catch block.
     */
	public List<String> getNestingInfoLines() {
		List<String> lines = new ArrayList<String>();

		var line = String.format("Catch (%s) (state=%d)"+"\t"+"@0x%s", getTypeName(), getState(), getAddressString());
		if (line.contains("(state=-2)"))
			line = line.replace("(state=-2)", "(state=?)");

		// Anything nested in a catch block?
		if (nested.size() == 0) {
			// Nothing nested.
			line += " {}";
			lines.add(line);
		}
		else {
			// Yes, something nested.
			line += " {";
			lines.add(line);				

			for (var nestedTryBlockmapEntry : nested) {
				var nestedLines = nestedTryBlockmapEntry.getNestingInfoLines();
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
