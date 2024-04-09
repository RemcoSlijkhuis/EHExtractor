package msvc.exceptions;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerModel;
import ghidra.app.cmd.data.exceptionhandling.EHTryBlockModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;

public class TryBlockMapEntryFactory {

	public List<TryBlockMapEntry> getTryBlockMapEntries(EHTryBlockModel tryBlockMap, int nTryBlocks) throws InvalidDataTypeException {
		List<TryBlockMapEntry> tryBlockMapEntries = new ArrayList<TryBlockMapEntry>();
		for (int i=0; i<nTryBlocks; i++) {
			TryBlockMapEntry tryBlockMapEntry = getTryBlockMapEntry(tryBlockMap, i);
			tryBlockMapEntries.add(tryBlockMapEntry);
		}
		return tryBlockMapEntries;
	}

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

		/* Let's do this in recurse?
		// We can guess the state of a catch handler right now in some cases.
		if (tryLow == tryHigh && catchHigh == tryHigh+1) {
			for (CatchHandler catchHandler : catchHandlers) {
				catchHandler.setState(catchHigh);
			}
		}
		*/
		
		return new TryBlockMapEntry(mapIndex, tryLow, tryHigh, catchHigh, nCatches, pHandlerArray, tryBlock, catchHandlers);
	}
}
