package msvc.exceptions;

import java.util.HashMap;

import ghidra.app.cmd.data.exceptionhandling.EHUnwindModel;
import ghidra.program.model.data.InvalidDataTypeException;

/**
 * Factory class for creating UnwindMap instances based on an EHUnwindModel.
 */
public class UnwindMapFactory {

    /**
     * Creates an UnwindMap from the provided EHUnwindModel.
     *
     * @param unwindModel The EHUnwindModel from which to extract unwind information (state transitions).
     * @return An UnwindMap containing the unwind information from unwindModel.
     * @throws InvalidDataTypeException if any errors occur while accessing data from unwindModel.
     */
	public static UnwindMap getUnwindMap(EHUnwindModel unwindModel) throws InvalidDataTypeException {
		var unwindMap = new HashMap<Integer, Integer>();
		for (var unwindOrdinal = 0; unwindOrdinal < unwindModel.getCount(); unwindOrdinal++) {
			var toState = unwindModel.getToState(unwindOrdinal);
			unwindMap.put(unwindOrdinal, toState);
		}
		return new UnwindMap(unwindMap);
	}
}
