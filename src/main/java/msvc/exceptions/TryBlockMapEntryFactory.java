package msvc.exceptions;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerModel;
import ghidra.app.cmd.data.exceptionhandling.EHTryBlockModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;

/**
 * Factory class for creating TryBlockMapEntries.
 */
public class TryBlockMapEntryFactory {

	/**
     * Creates a list of TryBlockMapEntry instances based on the provided tryBlockMap
     * and the specified number of TryBlockMapEntries.
     *
     * @param tryBlockMap The model containing try block information.
     * @param nTryBlocks The number of TryBlockMapEntries in tryBlockMap.
     * @return A list of TryBlockMapEntry instances.
     * @throws InvalidDataTypeException If there is a problem accessing the tryBlockMap.
     */
	public List<TryBlockMapEntry> getTryBlockMapEntries(EHTryBlockModel tryBlockMap, int nTryBlocks) throws InvalidDataTypeException {
		List<TryBlockMapEntry> tryBlockMapEntries = new ArrayList<TryBlockMapEntry>();
		for (int i=0; i<nTryBlocks; i++) {
			TryBlockMapEntry tryBlockMapEntry = getTryBlockMapEntry(tryBlockMap, i);
			tryBlockMapEntries.add(tryBlockMapEntry);
		}
		return tryBlockMapEntries;
	}

	/**
     * Creates a TryBlockMapEntry instance from the tryBlockMap for the specified index.
     *
     * @param tryBlockMap The EHTryBlockModel representing the TryBlockMap.
     * @param index The TryBlockMapEntry index to use.
     * @return A TryBlockMapEntry instance.
     * @throws InvalidDataTypeException If there is a problem accessing the tryBlockMap.
     */
	private TryBlockMapEntry getTryBlockMapEntry(EHTryBlockModel tryBlockMap, int index) throws InvalidDataTypeException {
		int mapIndex = index;
		int tryLow = tryBlockMap.getTryLow(index);
		int tryHigh = tryBlockMap.getTryHigh(index);
		int catchHigh = tryBlockMap.getCatchHigh(index);
		int nCatches = tryBlockMap.getCatchHandlerCount(index);
		Address pHandlerArray = tryBlockMap.getCatchHandlerMapAddress(index);
		
		TryBlock tryBlock = new TryBlock(tryLow, tryHigh);

		EHCatchHandlerModel catchHandlerModel = tryBlockMap.getCatchHandlerModel(index);		// What pHandlerArray in TryBlockMapEntry <index> points to.
		CatchHandlerFactory catchHandlerFactory = new CatchHandlerFactory();
		List<CatchHandler> catchHandlers = catchHandlerFactory.getCatchHandlers(catchHandlerModel, nCatches);
		
		return new TryBlockMapEntry(mapIndex, tryLow, tryHigh, catchHigh, nCatches, pHandlerArray, tryBlock, catchHandlers);
	}
}
