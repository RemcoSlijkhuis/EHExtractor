package instructionpattrns;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.Instruction;

/**
 * Represents an instruction pattern for matching the NOP instruction.
 */
public class NopInstructionPattern extends InstructionPattern {
	private String mnemonic = "NOP";

	/**
	 * Creates an instruction pattern for matching the nOP instruction.
	 */
	public NopInstructionPattern() {
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

		if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
			return false;
		if (instProto.getNumOperands() != 0)
			return false;

		return true;
	}
	
}
