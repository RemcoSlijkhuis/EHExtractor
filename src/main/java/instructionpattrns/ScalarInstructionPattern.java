package instructionpattrns;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

/**
 * Represents an instruction pattern for matching instructions that involve scalar non-address values.
 */
public class ScalarInstructionPattern extends InstructionPattern {
	String mnemonic = "";
	String register = "";
	Integer scalarValue = null;

	Scalar actualScalar = null;

	/**
     * Creates an instruction pattern for matching instructions with a specific mnemonic and scalar value (e.g. PUSH -1).
     *
     * @param mnemonic The instruction mnemonic to match.
     * @param scalarValue The scalar value in the instruction to match.
     */
	public ScalarInstructionPattern(String mnemonic, Integer scalarValue) {
		this.mnemonic = mnemonic;
		this.scalarValue = scalarValue;
	}

	/**
     * Creates an instruction pattern for matching instructions with a specific mnemonic and register, and any scalar value (e.g. MOV EAX, 12).
     *
     * @param mnemonic The instruction mnemonic to match.
     * @param register The register used in the instruction.
     * @param scalarClass The Scalar class type.
     */
	public ScalarInstructionPattern(String mnemonic, String register, Class<Scalar> scalarClass) {
		this.mnemonic = mnemonic;
		this.register = register;
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
	protected boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto) {
		
		if (this.register.equals("")) {
			// Instruction pattern is a specific mnemonic and scalar value (e.g. PUSH -1).
			
			// Do the mnemonic and the number of operands match?
			if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
				return false;
			if (instProto.getNumOperands() != 1)
				return false;

			// Check the operand.
			for (int opInd=0; opInd<1; opInd++) {
				Object[] opObjects = instProto.getOpObjects(opInd, instContext);
				if (opObjects.length != 1)
					return false;
				
				Object opObject = opObjects[opInd];
				
				// is it a scalar?
				if (!(opObject instanceof Scalar))
					return false;
				
				// Yes, it's a scalar. Now compare the value.
				Scalar scalar = (Scalar)opObject;
				if (scalar.bitLength() != 32)	// TODO hardwire!
					return false;
				if (this.scalarValue != null && this.scalarValue != scalar.getSignedValue())
					return false;		

				// We have a match. Store the actual scalar, we might have a use for it.
				this.actualScalar = scalar;
			}
		}
		else {
			// Instruction pattern is a specific mnemonic and register, and any scalar value (e.g. MOV EAX, 12).
			
			// Do the mnemonic and the number of operands match?
			if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
				return false;
			if (instProto.getNumOperands() != 2)
				return false;

			// Check the operands.
			for (int opInd=0; opInd<2; opInd++) {
				Object[] opObjects = instProto.getOpObjects(opInd, instContext);
				if (opObjects.length != 1)
					return false;

				Object opObject = opObjects[0];

				if (opInd == 0) {
					// First operand a register, and the right one?
					Register reg = toRegister(opObject);
					if (reg == null || !reg.getName().equals(this.register))
						return false;					
				}
				if (opInd == 1) {
					// Second operand a scalar, and a matching one?
					if (!(opObject instanceof Scalar))
						return false;

					// Now compare the value.
					Scalar scalar = (Scalar)opObject;
					if (scalar.bitLength() != 32)	// hardwire!
						return false;
					if (this.scalarValue != null && this.scalarValue != scalar.getSignedValue())
						return false;
					
					// We have a match. Store the actual scalar, we might have a use for it.
					this.actualScalar = scalar;
				}
			}
		}
		return true;
	}

	/**
     * Returns the actual scalar value matched by the instruction pattern.
     *
     * @return The scalar value, if the instruction matched the pattern successfully; otherwise, null.
     */
	public Scalar getActualScalar() {
		return this.actualScalar;
	}

}
