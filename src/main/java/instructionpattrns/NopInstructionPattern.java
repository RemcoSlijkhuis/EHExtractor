package instructionpattrns;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.Instruction;

public class NopInstructionPattern extends InstructionPattern {
	private String mnemonic = "NOP";

	public NopInstructionPattern() {
	}

//	@Override
//	public String toString() {
//		return mnemonic;
//	}

	@Override
	public boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto) {

		if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
			return false;
		if (instProto.getNumOperands() != 0)
			return false;

		return true;
	}
	
}
