package msvc.exceptions;

import java.util.HashMap;

import ghidra.app.cmd.data.exceptionhandling.EHUnwindModel;
import ghidra.program.model.data.InvalidDataTypeException;

public class UnwindMapFactory {

	public static UnwindMap getUnwindMap(EHUnwindModel unwindModel) throws InvalidDataTypeException {
		var unwindMap = new HashMap<Integer, Integer>();
		for (var unwindOrdinal = 0; unwindOrdinal < unwindModel.getCount(); unwindOrdinal++) {
			var toState = unwindModel.getToState(unwindOrdinal);
			unwindMap.put(unwindOrdinal, toState);
		}
		return new UnwindMap(unwindMap);
	}
}
