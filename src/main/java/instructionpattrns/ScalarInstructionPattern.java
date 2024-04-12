package instructionpattrns;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class ScalarInstructionPattern extends InstructionPattern {
	String mnemonic = "";
	String register = "";
	Integer scalarValue = null;

	Scalar actualScalar = null;

	public ScalarInstructionPattern(String mnemonic, Integer scalarValue) {
		this.mnemonic = mnemonic;
		this.scalarValue = scalarValue;
	}

	public ScalarInstructionPattern(String mnemonic, String register, Class<Scalar> scalarClass) {
		this.mnemonic = mnemonic;
		this.register = register;
	}
	
	@Override
	protected boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto) {
		
		if (this.register.equals("")) {
			if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
				return false;
			if (instProto.getNumOperands() != 1)
				return false;

			for (int opInd=0; opInd<1; opInd++) {
				Object[] opObjects = instProto.getOpObjects(opInd, instContext);
				if (opObjects.length != 1)
					return false;
				
				Object opObject = opObjects[opInd];
				
				// Scalar?
				if (!(opObject instanceof Scalar))
					return false;
				
				// Now compare the value.
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
			if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
				return false;
			if (instProto.getNumOperands() != 2)
				return false;

			for (int opInd=0; opInd<2; opInd++) {
				Object[] opObjects = instProto.getOpObjects(opInd, instContext);
				if (opObjects.length != 1)
					return false;

				Object opObject = opObjects[0];

				if (opInd == 0) {
					Register reg = toRegister(opObject);
					if (reg == null || !reg.getName().equals(this.register))
						return false;					
				}
				if (opInd == 1) {
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

	public Scalar getActualScalar() {
		return this.actualScalar;
	}

}
