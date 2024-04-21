package instructionpattrns;

import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.Register;

/**
 * Represents an instruction pattern for matching instructions that involve addresses, using either direct (e.g. JMP 12345678) or indirect (e.g. MOV EAX, [EDX+10]) addressing modes.
 */
public class AddressInstructionPattern extends InstructionPattern {
	private InstructionType instructionType = InstructionType.Direct; 
	
	String mnemonic = "";
	Integer genericAddressValue = null; 
	Function function = null;
	boolean matchThunks = false;
	String destinationRegister = null;
	String sourceRegister = null;
	Long scalarOffset = 0L;
	boolean specificScalar = false;

	/**
	 * Enumerates the two possible addressing modes.
	 */
	enum InstructionType {
		Direct,
		Indirect
	}
	
	/**
     * Returns the actual scalar offset value used by the matching instruction (in the case of indirect addressing).
     *
     * @return The scalar offset as a Long value, if the instruction matched the pattern successfully; otherwise, null.
     */
	public Long getScalarOffset() {
		return this.scalarOffset;
	}

	/**
     * Creates an instruction pattern for matching instructions involving an address and using direct addressing mode (e.g. CALL &lt;any address%gt;).
     *
     * @param mnemonic The mnemonic of the instruction to match.
     * @param genericAddressClass The class type for matching generic address.
     */
	public AddressInstructionPattern(String mnemonic, Class<GenericAddress> genericAddressClass) {
		instructionType = InstructionType.Direct;

		this.mnemonic = mnemonic;
		this.genericAddressValue = null;
		this.function = null;
		this.matchThunks = false;
		this.destinationRegister = null;
		this.sourceRegister = null;
		this.scalarOffset = 0L;
		this.specificScalar = false;
	}

	/**
     * Creates an instruction pattern for matching instructions involving a function and using direct addressing mode (e.g. CALL %lt;some function%gt;).
     *
     * @param mnemonic The instruction mnemonic to match.
     * @param function The function involved in the instruction.
     * @param matchThunks Whether or not to match thunks associated with the function.
     */
	public AddressInstructionPattern(String mnemonic, Function function, boolean matchThunks) {
		instructionType = InstructionType.Direct;

		this.mnemonic = mnemonic;
		this.genericAddressValue = null;
		this.function = function;
		this.matchThunks = matchThunks;
		this.destinationRegister = null;
		this.sourceRegister = null;
		this.scalarOffset = 0L;
		this.specificScalar = false;
	}

	/**
	 * Creates an instruction pattern for matching instructions involving two registers and an offset, and using direct addressing mode (e.g. LEA EAX, [EDX + 0ch]).
     * 
	 * @param mnemonic The instruction mnemonic to match.
	 * @param destinationRegister The destination (first) register.
	 * @param sourceRegister The source (second) register.
	 * @param scalarOffset The offset to use with respect to the source register value.
	 */
	public AddressInstructionPattern(String mnemonic, String destinationRegister, String sourceRegister, Long scalarOffset) {
		instructionType = InstructionType.Indirect;

		this.mnemonic = mnemonic;
		this.genericAddressValue = null;
		this.function = null;
		this.matchThunks = false;
		this.destinationRegister = destinationRegister;
		this.sourceRegister = sourceRegister;
		this.scalarOffset = scalarOffset;
		this.specificScalar = true;
	}

	/**
	 * Creates an instruction pattern for matching instructions involving two registers and any offset, and using direct addressing mode (e.g. MOV ECX, [EDX + %lt;any scalar offset%gt;]).
     * 
	 * @param mnemonic The instruction mnemonic to match.
	 * @param destinationRegister The destination (first) register.
	 * @param sourceRegister The source (second) register.
	 * @param scalarClass The Scalar class type.
	 */
	public AddressInstructionPattern(String mnemonic, String destinationRegister, String sourceRegister, Class<Scalar> scalarClass) {
		instructionType = InstructionType.Indirect;

		this.mnemonic = mnemonic;
		this.genericAddressValue = null;
		this.function = null;
		this.matchThunks = false;
		this.destinationRegister = destinationRegister;
		this.sourceRegister = sourceRegister;
		this.scalarOffset = 0L;
		this.specificScalar = false;
	}

	/**
     * Checks if the provided instruction matches this instruction pattern.
     *
     * @param inst The instruction to be checked.
     * @param instContext The instruction context of the instruction.
     * @param instProto The instruction prototype of the instruction.
     * @return true if the instruction matches the instruction pattern, false otherwise.
     */
	@Override
	public boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto) {
		
		if (this.instructionType == InstructionType.Indirect)
			return matchesImplIndirect(inst, instContext, instProto);

		if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
			return false;
		if (instProto.getNumOperands() != 1)
			return false;

		for (int opInd=0; opInd<1; opInd++) {
			Object[] opObjects = instProto.getOpObjects(opInd, instContext);
			if (opObjects.length != 1)
				return false;

			if (opInd == 0) {
				Object opObject = opObjects[0];

				// We expect an address.
				if (!(opObject instanceof GenericAddress))
					return false;

				GenericAddress genericAddress = (GenericAddress)opObject;

				// Do we care about the actual address?
				if (function == null && this.genericAddressValue == null) {
					// No, all good.
					return true;
				}
				else if (function == null && this.genericAddressValue != null) {
					// Yes, address specified and it must match.
					if (!this.genericAddressValue.equals(genericAddress.getOffset()))
						return false;		
				}
				else if (function != null && !matchThunks) {
					// Function address must match precisely.
					Address functionAddress = this.function.getEntryPoint();
					if (!functionAddress.equals(genericAddress))	// TODO Does this actually work?
						return false;
				}
				else if (function != null && matchThunks) {				
					// Function specified and it's ok if the address in this instruction
					// matches the address of this function or of one of its (possible) thunks.
					Address functionAddress = this.function.getEntryPoint();

					if (functionAddress.equals(genericAddress))
						return true;

					var thunkAddresses = this.function.getFunctionThunkAddresses(true);
					if (thunkAddresses != null) {
						for (Address thunkAddress : thunkAddresses) {
							if (thunkAddress.equals(genericAddress))
								return true;
						}
					}
					
					return false;					
				}
				
			}	
		}

		return true;
	}
	
	private boolean matchesImplIndirect(Instruction inst, InstructionContext instContext, InstructionPrototype instProto) {
		if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
			return false;
		if (instProto.getNumOperands() != 2)
			return false;

		for (int opInd=0; opInd<2; opInd++) {
			Object[] opObjects = instProto.getOpObjects(opInd, instContext);

			if (opInd == 0) {
				if (opObjects.length != 1)
					return false;
				
				Register reg = toRegister(opObjects[0]);
				if (reg == null || !reg.getName().equals(this.destinationRegister)) {
					Logger.getLogger("EHExtractor").log(Level.FINER, "Issue with the destination.");
					return false;
				}
			}
			else if (opInd == 1) {
				if (opObjects.length != 2)
					return false;

				Register reg = toRegister(opObjects[0]);
				if (reg == null || !reg.getName().equals(this.sourceRegister)) {
					Logger.getLogger("EHExtractor").log(Level.FINER, "Issue with the source.");
					return false;
				}

				Scalar scalar = toScalar(opObjects[1]);
				if (scalar == null || (specificScalar && scalar.getValue() != this.scalarOffset)) {
					Logger.getLogger("EHExtractor").log(Level.FINER, "Issue with the scalar.");
					return false;
				}
				else if (!specificScalar) {
					this.scalarOffset = scalar.getValue();
				}
			}			
		}		
		return true;
	}
	
}
