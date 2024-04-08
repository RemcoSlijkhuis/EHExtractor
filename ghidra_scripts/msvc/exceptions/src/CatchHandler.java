package msvc.exceptions.src;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerTypeModifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.scalar.Scalar;

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

	// NOTE: Builder pattern without .build()!
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


	// ITryCatch methods.
	public BlockType getBlockType() {
		return BlockType.CATCH;
	}

	public int getState() {
		return state;
	}

	public void setState(int state) {
		if (state < -1)
			throw new IllegalArgumentException("A catch block's state cannot be < -1.");
		this.state = state;
	}

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

	public boolean hasValidState() {
		return state >= -1;
	}

	public void nest(TryBlockMapEntry tryBlockMapEntry) {
		nested.add(tryBlockMapEntry);
	}

	//
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
	
	public List<String> getInfoLines() {
		List<String> lines = new ArrayList<String>();

		lines.add("adjectives: " + String.format("%08x", adjectives.hashCode()));
		lines.add("pType: " + pType);
		lines.add("dispCatchObj: " + dispCatchObj);
		lines.add("address: " + address);
		lines.add("typeDescriptor: " + typeDescriptor);
		lines.add("type name: " + typeName);
		lines.add("handler name: " + handlerName);
		if (typeDescriptor != null) {
			lines.add("getDemangledTypeDescriptor: " + typeDescriptor.getDemangledTypeDescriptor());
			lines.add("getDescriptorName: " + typeDescriptor.getDescriptorName());
			try {
				lines.add("getTypeName: " + typeDescriptor.getTypeName());
			} catch (InvalidDataTypeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			lines.add("getRefType: " + typeDescriptor.getRefType());
			lines.add("getParentNamespace: " + typeDescriptor.getParentNamespace());
			lines.add("getDescriptorTypeNamespace: " + typeDescriptor.getDescriptorTypeNamespace());
			
		}
		
		return lines;
	}

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
