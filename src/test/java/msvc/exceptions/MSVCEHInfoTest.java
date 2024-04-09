package msvc.exceptions;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import ghidra.app.cmd.data.exceptionhandling.EHUnwindModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;

import msvc.exceptions.*;

public class MSVCEHInfoTest {

	protected TryBlockMapEntry tryBlockMapEntry0;
	protected TryBlockMapEntry tryBlockMapEntry2;

	protected List<String> tryBlockMapEntry0_overview;
	protected List<String> tryBlockMapEntry2_overview;
	
	private NestedStructureParser nsp;
	private Path workingDir;
	private File testFile1;
	private File testFile1AfterRecurse;
	private File testFile2;
	private File testFile2AfterRecurse;
	private File testFile2SingleCatch;
	private File testFile2SingleCatchAfterRecurse;
	private File testFile2Simple;
	private File testFile2SimpleAfterRecurse;
	private File testFile2SuperSimple;
	private File testFile2SuperSimpleAfterRecurse;
	
	@Before
	public void setUp() throws Exception {
		int mapIndex = 0;
		int tryLow = 0;
		int tryHigh = 0;
		int catchHigh = 1;
		int nCatches = 1;
		Address pHandlerArray = null;
		List<CatchHandler> catchHandlers = new ArrayList<CatchHandler>();
		
		TryBlock tryBlock = new TryBlock(tryLow, tryHigh);
		TryBlock tryBlock2 = new TryBlock(tryLow+2, tryHigh+2);
		
		CatchHandlerFactory catchHandlerFactory = new CatchHandlerFactory();
		CatchHandler catchHandler = catchHandlerFactory.createSimpleCatchHandler("Some handler");
		catchHandlers.add(catchHandler);

		tryBlockMapEntry0 = new TryBlockMapEntry(mapIndex, tryLow, tryHigh, catchHigh, nCatches, pHandlerArray, tryBlock, catchHandlers);
		tryBlockMapEntry2 = new TryBlockMapEntry(mapIndex+1, tryLow+2, tryHigh+2, catchHigh+2, nCatches, pHandlerArray, tryBlock2, catchHandlers);

		tryBlockMapEntry0_overview = new ArrayList<String>();
		tryBlockMapEntry0_overview.add("/* TryBlockMapEntry [0]\t0-0,1,1 */");
		tryBlockMapEntry0_overview.add("Try (state=0) {}");
		tryBlockMapEntry0_overview.add("Catch (...) (state=?)\t@0x00000000 {}");

		tryBlockMapEntry2_overview = new ArrayList<String>();
		tryBlockMapEntry2_overview.add("/* TryBlockMapEntry [1]\t2-2,3,1 */");
		tryBlockMapEntry2_overview.add("Try (state=2) {}");
		tryBlockMapEntry2_overview.add("Catch (...) (state=?)\t@0x00000000 {}");
		
		
		nsp = new NestedStructureParser();
		
		ClassLoader classLoader = getClass().getClassLoader();
		testFile1 = new File(classLoader.getResource("nestedtest1.txt").getFile());
		testFile1AfterRecurse = new File(classLoader.getResource("nestedtest1_afterRecurse.txt").getFile());

		testFile2 = new File(classLoader.getResource("nestedtest2.txt").getFile());
		testFile2AfterRecurse = new File(classLoader.getResource("nestedtest2_afterRecurse.txt").getFile());
		//
		testFile2SingleCatch = new File(classLoader.getResource("nestedtest2_singleCatch.txt").getFile());
		testFile2SingleCatchAfterRecurse = new File(classLoader.getResource("nestedtest2_singleCatch_afterRecurse.txt").getFile());
		//
		testFile2Simple = new File(classLoader.getResource("nestedtest2_simple.txt").getFile());
		testFile2SimpleAfterRecurse = new File(classLoader.getResource("nestedtest2_simple_afterRecurse.txt").getFile());
		testFile2SuperSimple = new File(classLoader.getResource("nestedtest2_superSimple.txt").getFile());
		testFile2SuperSimpleAfterRecurse = new File(classLoader.getResource("nestedtest2_superSimple_afterRecurse.txt").getFile());
	}

	//@Test
	//public void testMSVCEHInfo() {
	//	fail("Not yet implemented");
	//}
	
	@Test
	public void testDetermineLayoutList() throws IOException {
		var tryBlockMapEntries = new ArrayList<TryBlockMapEntry>();
		tryBlockMapEntries.add(tryBlockMapEntry0);
		tryBlockMapEntries.add(tryBlockMapEntry2);
		
		assertTrue(tryBlockMapEntries.get(0).getTryLow() < tryBlockMapEntries.get(1).getTryLow());
		
		var outerTryBlockMapEntries = MSVCEHInfo.determineLayout(tryBlockMapEntries);
		assertTrue(tryBlockMapEntries.get(0).getTryLow() > tryBlockMapEntries.get(1).getTryLow());
		assertEquals(2, outerTryBlockMapEntries.size());

		List<String> overviewAfterDetermineLayout = MSVCEHInfo.getTryCatchBlockOverview(outerTryBlockMapEntries, "");
		
		List<String> tryBlockMapEntry02_overview = new ArrayList<String>();
		tryBlockMapEntry02_overview.addAll(tryBlockMapEntry0_overview);
		tryBlockMapEntry02_overview.addAll(tryBlockMapEntry2_overview);
		assertOverview(tryBlockMapEntry02_overview, overviewAfterDetermineLayout);
	}

	@Test
	public void recurseWithNullUnwindMap() throws InvalidDataTypeException {
		TryBlockMapEntry current = tryBlockMapEntry0;
		ITryCatch parent = null;
		HashSet<Integer> knownStates = new HashSet<Integer>();
		UnwindMap unwindMap = null;
		String prefix = "";

		var linesOrig = current.getNestingInfoLines();
		MSVCEHInfo.recurse(current, parent, knownStates, unwindMap, prefix);		
		var linesNew = current.getNestingInfoLines();
		assertEquals(linesOrig, linesNew);
	}
	
	@Test
	public void recurseWithSimpleUnwindMap() throws InvalidDataTypeException {
		TryBlockMapEntry current = tryBlockMapEntry0;
		ITryCatch parent = null;
		HashSet<Integer> knownStates = new HashSet<Integer>();
		String prefix = "";

		UnwindMap unwindMap = new UnwindMap();
		unwindMap.add(0,  -1);
		unwindMap.add(1,  -1);

		var linesOrig = current.getNestingInfoLines();
		MSVCEHInfo.recurse(current, parent, knownStates, unwindMap, prefix);		
		var linesNew = current.getNestingInfoLines();
		assertNotEquals(linesOrig, linesNew);
	}

	@Test
	public void recurseSuperSimple() throws InvalidDataTypeException, IOException {
		// ExceptionVS32_Yes_EHsc_GS-_GR-.exe, function B but with only one catch in each TryBlockMapEntry and no state gaps.
		// Also, there is only one TryBlockMapEntry.
		var outerTryBlockMapEntries = nsp.parseFile(testFile2SuperSimple);
		UnwindMap unwindMap = new UnwindMap();
		unwindMap.add(0, -1);
		unwindMap.add(1, -1);

		HashSet<Integer> knownStates = new HashSet<Integer>();
		for (var outer : outerTryBlockMapEntries) {
			MSVCEHInfo.recurse(outer, null, knownStates, unwindMap, "");
		}

		List<String> overviewAfterRecurse = MSVCEHInfo.getTryCatchBlockOverview(outerTryBlockMapEntries, "");
		assertOverview(testFile2SuperSimpleAfterRecurse, overviewAfterRecurse);
	}

	@Test
	public void recurseSimple() throws InvalidDataTypeException, IOException {
		// ExceptionVS32_Yes_EHsc_GS-_GR-.exe, function B but with only one catch in each TryBlockMapEntry and no state gaps.
		// Current problem here is that there are multiple TryBlockMapEntries at the same (outmost-)level. 
		var outerTryBlockMapEntries = nsp.parseFile(testFile2Simple);
		UnwindMap unwindMap = new UnwindMap();
		unwindMap.add(0, -1);
		unwindMap.add(1, -1);
		unwindMap.add(2, -1);
		unwindMap.add(3, -1);
		unwindMap.add(4, -1);
		unwindMap.add(5, -1);

		HashSet<Integer> knownStates = new HashSet<Integer>();
		for (var outer : outerTryBlockMapEntries) {
			MSVCEHInfo.recurse(outer, null, knownStates, unwindMap, "");
		}

		List<String> overviewAfterRecurse = MSVCEHInfo.getTryCatchBlockOverview(outerTryBlockMapEntries, "");
		assertOverview(testFile2SimpleAfterRecurse, overviewAfterRecurse);
	}

	@Test
	public void recurseWithoutStateGap() throws InvalidDataTypeException, IOException {
		// NestedExceptionVS32_EHsc_GS-_GR-.exe, function Nested6.
		// Problem: Has 2 TryBlockMapEntries that need to be nested in catches.
		var outerTryBlockMapEntries = nsp.parseFile(testFile1);
		UnwindMap unwindMap = new UnwindMap();
		unwindMap.add(0, -1);
		unwindMap.add(1, 0);
		unwindMap.add(2, 1);
		unwindMap.add(3, 2);
		unwindMap.add(4, 2);
		unwindMap.add(5, 1);
		unwindMap.add(6, 0);
		unwindMap.add(7, 6);
		unwindMap.add(8, 6);
		unwindMap.add(9, 8);
		unwindMap.add(10, 8);
		unwindMap.add(11, 8);
		unwindMap.add(12, 8);

		HashSet<Integer> knownStates = new HashSet<Integer>();
		for (var outer : outerTryBlockMapEntries) {
			MSVCEHInfo.recurse(outer, null, knownStates, unwindMap, "");
		}
		
		List<String> overviewAfterRecurse = MSVCEHInfo.getTryCatchBlockOverview(outerTryBlockMapEntries, "");
		assertOverview(testFile1AfterRecurse, overviewAfterRecurse);
	}

	@Test
	public void recurseWithStateGapSingleCatch() throws InvalidDataTypeException, IOException {
		// ExceptionVS32_Yes_EHsc_GS-_GR-.exe, function B but with only one catch in each TryBlockMapEntry.
		var outerTryBlockMapEntries = nsp.parseFile(testFile2SingleCatch);
		UnwindMap unwindMap = new UnwindMap();
		unwindMap.add(0, -1);
		unwindMap.add(1, -1);
		unwindMap.add(2, -1);
		unwindMap.add(3, -1);
		unwindMap.add(4, -1);
		unwindMap.add(5, 4);
		unwindMap.add(6, 4);

		HashSet<Integer> knownStates = new HashSet<Integer>();
		for (var outer : outerTryBlockMapEntries) {
			MSVCEHInfo.recurse(outer, null, knownStates, unwindMap, "");
		}

		List<String> overviewAfterRecurse = MSVCEHInfo.getTryCatchBlockOverview(outerTryBlockMapEntries, "");
		assertOverview(testFile2SingleCatchAfterRecurse, overviewAfterRecurse);
	}

	@Test
	public void recurseWithStateGapMultipleCatches() throws InvalidDataTypeException, IOException {
		// ExceptionVS32_Yes_EHsc_GS-_GR-.exe, function B.
		// State gap and multiple catches in the last TryBlockMapEntry.
		var outerTryBlockMapEntries = nsp.parseFile(testFile2);
		UnwindMap unwindMap = new UnwindMap();
		unwindMap.add(0, -1);
		unwindMap.add(1, -1);
		unwindMap.add(2, -1);
		unwindMap.add(3, -1);
		unwindMap.add(4, -1);
		unwindMap.add(5, 4);
		unwindMap.add(6, 4);

		HashSet<Integer> knownStates = new HashSet<Integer>();
		for (var outer : outerTryBlockMapEntries) {
			MSVCEHInfo.recurse(outer, null, knownStates, unwindMap, "");
		}

		List<String> overviewAfterRecurse = MSVCEHInfo.getTryCatchBlockOverview(outerTryBlockMapEntries, "");
		assertOverview(testFile2AfterRecurse, overviewAfterRecurse);
	}
	
	//--- Helper functions ----------------------------------------------------------------
	private void assertOverview(File expectedOverviewFile, List<String> actualOverview) throws IOException {
		List<String> expectedOverview = readLinesFromFile(expectedOverviewFile);
		assertOverview(expectedOverview, actualOverview);
	}

	private void assertOverview(List<String> expectedOverview, List<String> actualOverview) throws IOException {
		int i = 0;
		int j = 0;
		while (i < expectedOverview.size() && j < actualOverview.size()) {
			String expectedLine = expectedOverview.get(i).trim();
			if (expectedLine.startsWith("//") || expectedLine.equals("")) {
				i++;
				continue;
			}

			String actualLine = actualOverview.get(j).trim();
			if (actualLine.startsWith("//") || actualLine.equals("")) {
				j++;
				continue;
			}

			assertEquals(expectedLine, actualLine);
			i++;
			j++;
		}
		assertEquals(expectedOverview.size(), i);
		assertEquals(actualOverview.size(), j);
	}

	private List<String> readLinesFromFile(File file) throws IOException {
		List<String>lines = new ArrayList<String>();

		BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
        	lines.add(line);
        }
        reader.close();

        return lines;
	}

}
