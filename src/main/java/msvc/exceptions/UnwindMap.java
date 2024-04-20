package msvc.exceptions;

import java.util.HashMap;

import ghidra.program.model.data.InvalidDataTypeException;

/**
 * Provides the same functionality as EHUnwindModel, i.e. managing a map of unwind states.
 */
public class UnwindMap {

	HashMap<Integer, Integer> unwindMap;
	
	/**
     * Constructs an empty UnwindMap.
     */
	public UnwindMap() {
		unwindMap = new HashMap<Integer, Integer>();	
	}

	/**
     * Constructs an UnwindMap with an existing map of state transitions.
     * 
     * @param unwindMap The initial map of state transitions.
     */
	public UnwindMap(HashMap<Integer, Integer> unwindMap) {
		this.unwindMap = unwindMap;
	}
	
	/**
     * Adds a state transition to the map.
     * 
     * @param fromState The starting state.
     * @param toState The target state.
     */
	public void add(Integer fromState, Integer toState) {
		unwindMap.put(fromState,  toState);
	}
	
	/**
     * Returns the number of state transitions in the map.
     * 
     * @return The number of transitions.
     */
	public int getCount() {
		return unwindMap.size();		
	}

	/**
     * Retrieves the target state for a given starting state.
     * 
     * @param fromState The 'current' state.
     * @return The state to which the unwinding leads.
     * @throws InvalidDataTypeException if the fromState is not found in the map.
     */
	public Integer getToState(Integer fromState) throws InvalidDataTypeException {
		if (!unwindMap.containsKey(fromState)) {
			throw new InvalidDataTypeException();
		}
		return unwindMap.get(fromState);
	}
}
