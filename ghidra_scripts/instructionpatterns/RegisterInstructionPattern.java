package instructionpatterns;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class RegisterInstructionPattern extends InstructionPattern {

	String mnemonic = null;
	List<String> operands = null;
	
	public RegisterInstructionPattern(String mnemonic, String register1, String register2) {
		this.mnemonic = mnemonic;		
		this.operands = Arrays.asList(register1, register2);
	}

	public RegisterInstructionPattern(String mnemonic, List<String> operands) {
		this.mnemonic = mnemonic;
		this.operands = operands;
	}

	@Override
	protected boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto) {

		if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
			return false;
		if (instProto.getNumOperands() != this.operands.size())  //2)
			return false;

		for (int opInd=0; opInd<this.operands.size(); opInd++) {
			Object[] opObjects = instProto.getOpObjects(opInd, instContext);
			if (opObjects.length != 1)
				return false;
			
			Register reg = toRegister(opObjects[0]);
			if (reg == null || !reg.getName().equals(this.operands.get(opInd))) {
				Logger.getLogger("EHExtractor").log(Level.FINE, "Issue with register " + opInd);
				return false;
			}
		}

		return true;
	}

}
