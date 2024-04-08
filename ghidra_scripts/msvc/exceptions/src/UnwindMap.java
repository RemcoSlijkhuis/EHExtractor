package msvc.exceptions.src;

import java.util.HashMap;

import ghidra.program.model.data.InvalidDataTypeException;

/**
 * This class provides the same 'read functionality' as EHUnwindModel, but can also be instantiated without a full binary program (for ease of testing).
 */
public class UnwindMap {

	HashMap<Integer, Integer> unwindMap;
	
	public UnwindMap() {
		unwindMap = new HashMap<Integer, Integer>();	
	}

	public UnwindMap(HashMap<Integer, Integer> unwindMap) {
		this.unwindMap = unwindMap;
	}
	
	public void add(Integer fromState, Integer toState) {
		unwindMap.put(fromState,  toState);
	}
	
	public int getCount() {
		return unwindMap.size();		
	}

	public Integer getToState(Integer fromState) throws InvalidDataTypeException {
		if (!unwindMap.containsKey(fromState)) {
			throw new InvalidDataTypeException();
		}
		return unwindMap.get(fromState);
	}
}
