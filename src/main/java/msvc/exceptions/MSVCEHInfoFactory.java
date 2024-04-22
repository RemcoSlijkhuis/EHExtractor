package msvc.exceptions;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.app.cmd.data.exceptionhandling.EHESTypeListModel;
import ghidra.app.cmd.data.exceptionhandling.EHFunctionInfoModel;
import ghidra.app.cmd.data.exceptionhandling.EHIPToStateModel;
import ghidra.app.cmd.data.exceptionhandling.EHTryBlockModel;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.lang.UndefinedValueException;
import ghidra.program.model.listing.Program;

/**
 * Factory class to construct an MSVCEHInfo object from a given Ghidra program and FuncInfo data structure address.
 */
public class MSVCEHInfoFactory {

	/**
     * Creates an MSVCEHInfo object from a given Ghidra program and FuncInfo data structure address.
     * This method combines base FuncInfo properties and objects derived from data structures linked to FuncInfo into the MSVCEHInfo object.
     *
     * @param program The program from which to extract the FuncInfo and other linked information.
     * @param funcInfoAddress The address of a FuncInfo data structure.
     * @return MSVCEHInfo The created MSVCEHInfo object.
     * @throws InvalidDataTypeException If there is a problem processing the data structures.
     */
	public static MSVCEHInfo getMSVCEHInfo(Program program, Address funcInfoAddress) throws InvalidDataTypeException {
		Logger logger = Logger.getLogger("EHExtractor");
		
		// The properties about to be extracted.
		int magicNumber = 0;
		int bbtFlags = 0;
		int maxState = 0;
		Address pUnwindMap = null;
		int nTryBlocks = 0;
		Address pTryBlockMap = null;
		int nIPMapEntries = 0;
		Address pIPToStateMap = null;
		Address pESTypeList = null;
		int ehFlags = 0;

		UnwindMap unwindMap = null;
		List<TryBlockMapEntry> tryBlockMapEntries = null;
		
		// Here we go.
		DataValidationOptions validationOptions = new DataValidationOptions();
		EHFunctionInfoModel funcInfo = new EHFunctionInfoModel(program, funcInfoAddress, validationOptions);

		magicNumber = funcInfo.getMagicNumber();
		bbtFlags = funcInfo.getBbtFlags();
		maxState = funcInfo.getUnwindCount();
		pUnwindMap = funcInfo.getUnwindMapAddress();
		nTryBlocks = funcInfo.getTryBlockCount();
		pTryBlockMap = funcInfo.getTryBlockMapAddress();
		nIPMapEntries = funcInfo.getIPToStateCount();
		pIPToStateMap = funcInfo.getIPToStateMapAddress();
		pESTypeList = null;
		ehFlags = 0;
		try {
			pESTypeList = funcInfo.getESTypeListAddress();
			ehFlags = funcInfo.getEHFlags();
		}
		catch (UndefinedValueException e) {				
		}

		// UnwindMap / UnwindMapEntry_ARRAY
		var unwindModel = funcInfo.getUnwindModel();
		var unwindModelAddress = unwindModel.getAddress();
		if (!unwindModelAddress.equals(pUnwindMap)) {
			throw new InvalidDataTypeException("Unwind map address ("+unwindModelAddress+") does not match pUnwindMap value ("+pUnwindMap+")!", null);
		}			
		// Convert the EHUnwindModel object into an UnwindMap object with the same functions.
		unwindMap = UnwindMapFactory.getUnwindMap(unwindModel);

		// Try+Catch blocks
		if (nTryBlocks > 0 && pTryBlockMap != null) {
			// TryBlockMap / TryBlockMapEntry_ARRAY
			EHTryBlockModel tryBlockMap = funcInfo.getTryBlockModel();
			var tryBlockMapAddress =  tryBlockMap.getAddress();
			if (!tryBlockMapAddress.equals(pTryBlockMap)) {
				throw new InvalidDataTypeException("Try block map address ("+tryBlockMapAddress+") does not match pTryBlockMap value ("+pTryBlockMap+")!", null);
			}
			
			TryBlockMapEntryFactory tryBlockMapEntryFactory = new TryBlockMapEntryFactory();
			tryBlockMapEntries = tryBlockMapEntryFactory.getTryBlockMapEntries(tryBlockMap, nTryBlocks);
		} 

		// IPToStateMap
		EHIPToStateModel ipToStateMap = null;
		if (pIPToStateMap != null) {
			ipToStateMap = funcInfo.getIPToStateModel();
		}
		logger.log(Level.FINER, "Ignoring IPToStateMap information for now.");

		// ESTypeList
		EHESTypeListModel esTypeList = null;
		if (pESTypeList != null) {
			esTypeList = funcInfo.getEHESTypeListModel();
		}
		logger.log(Level.FINER, "Ignoring ESTypeList information for now.");

		// Instantiate MSVCEHInfo.
		return new MSVCEHInfo(magicNumber, bbtFlags, maxState, pUnwindMap, nTryBlocks,
				pTryBlockMap, nIPMapEntries, pIPToStateMap, pESTypeList, ehFlags,
				unwindMap, tryBlockMapEntries);
	}
}
