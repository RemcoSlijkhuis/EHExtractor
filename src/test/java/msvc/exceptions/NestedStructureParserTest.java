package msvc.exceptions;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * Unit tests for the parser for the output produced by EHExtractor, for use in unit tests.
 */
public class NestedStructureParserTest {

	private NestedStructureParser nsp;
	private Path workingDir;
	private File testFile1Old;
	private File testFile1;
	private File testFile2;
	private File testFile2Simple;

	@Before
	public void setUp() throws Exception {
		nsp = new NestedStructureParser();

		ClassLoader classLoader = getClass().getClassLoader();
		testFile1Old = new File(classLoader.getResource("nestedtest1Old.txt").getFile());				
		testFile1 = new File(classLoader.getResource("nestedtest1.txt").getFile());				
		testFile2 = new File(classLoader.getResource("nestedtest2.txt").getFile());				
		testFile2Simple = new File(classLoader.getResource("nestedtest2_simple.txt").getFile());				
	}

	//@Test
	public void testParseFile1Old() throws IOException {
		var outer = nsp.parseFile(testFile1Old);
		
		assertEquals(1, outer.size());

		var tryBlockMapEntry_5 = outer.get(0);
		assertEquals(5, tryBlockMapEntry_5.getMapIndex());
		assertEquals(1, tryBlockMapEntry_5.getTryLow());
		assertEquals(5, tryBlockMapEntry_5.getTryHigh());
		assertEquals(12, tryBlockMapEntry_5.getCatchHigh());
		assertEquals(1, tryBlockMapEntry_5.getNCatches());

		var tryBlock_1 = tryBlockMapEntry_5.getTryBlock();
		assertEquals(1, tryBlock_1.getState());
		assertEquals(5, tryBlock_1.getTryHigh());
		assertEquals(1, tryBlock_1.getNested().size());

		var tryBlockMapEntry_1 = tryBlock_1.getNested().get(0);
		assertEquals(1, tryBlockMapEntry_1.getMapIndex());
		assertEquals(2, tryBlockMapEntry_1.getTryLow());
		assertEquals(4, tryBlockMapEntry_1.getTryHigh());
		assertEquals(5, tryBlockMapEntry_1.getCatchHigh());
		assertEquals(1, tryBlockMapEntry_1.getNCatches());

		var tryBlock_2 = tryBlockMapEntry_1.getTryBlock();
		assertEquals(2, tryBlock_2.getState());
		assertEquals(4, tryBlock_2.getTryHigh());
		assertEquals(1, tryBlock_2.getNested().size());

		var tryBlockMapEntry_0 = tryBlock_2.getNested().get(0);
		assertEquals(0, tryBlockMapEntry_0.getMapIndex());
		assertEquals(3, tryBlockMapEntry_0.getTryLow());
		assertEquals(3, tryBlockMapEntry_0.getTryHigh());
		assertEquals(4, tryBlockMapEntry_0.getCatchHigh());
		assertEquals(1, tryBlockMapEntry_0.getNCatches());

		var tryBlock_3 = tryBlockMapEntry_0.getTryBlock();
		assertEquals(3, tryBlock_3.getState());
		assertEquals(3, tryBlock_3.getTryHigh());
		assertEquals(0, tryBlock_3.getNested().size());

		// Catch 3+?
		assertEquals(1, tryBlockMapEntry_0.getCatchHandlers().size());
		var catchHandler_x = tryBlockMapEntry_0.getCatchHandlers().get(0);
		assertEquals(-2, catchHandler_x.getState());
		assertEquals(0x0040196b, Integer.parseInt(catchHandler_x.getAddressString()));
		assertEquals(0, catchHandler_x.getNested().size());

		// Catch 2+?
		assertEquals(1, tryBlockMapEntry_1.getCatchHandlers().size());
		var catchHandler_y = tryBlockMapEntry_1.getCatchHandlers().get(0);
		assertEquals(-2, catchHandler_y.getState());
		assertEquals(0x0040198c, Integer.parseInt(catchHandler_y.getAddressString()));
		assertEquals(0, catchHandler_y.getNested().size());
		
		// Catch 1+?
		assertEquals(1, tryBlockMapEntry_5.getCatchHandlers().size());
		var catchHandler_z = tryBlockMapEntry_5.getCatchHandlers().get(0);
		assertEquals(-2, catchHandler_z.getState());
		assertEquals(0x004019b0, Integer.parseInt(catchHandler_z.getAddressString()));
		assertEquals(1, catchHandler_z.getNested().size());
		
		// TryBlockMapEntry [4]
		var tryBlockMapEntry_4 = catchHandler_z.getNested().get(0);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_4, 4, 7, 7, 12, 2);
		assertEquals(2, tryBlockMapEntry_4.getCatchHandlers().size());

		var tryBlock_7 = tryBlockMapEntry_4.getTryBlock();
		assertTryBlockProperties(tryBlock_7, 7, 7, 0);


		// Catch 7+?
		var catchHandler_u1 = tryBlockMapEntry_4.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_u1, -2, 0x004019c2);
		assertEquals(2, catchHandler_u1.getNested().size());

		// TryBlockMapEntry [3] #1
		var tryBlockMapEntry_3_1 = catchHandler_u1.getNested().get(0);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_3_1, 3, 11, 11, 12, 1);
		// Try 11
		var tryBlock_11 = tryBlockMapEntry_3_1.getTryBlock();
		assertTryBlockProperties(tryBlock_11, 11, 11, 0);
		// Catch 11+?
		var catchHandler_v = tryBlockMapEntry_3_1.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_v, -2, 0x00401a05);
		assertEquals(0, catchHandler_v.getNested().size());
		// TryBlockMapEntry [2]
		var tryBlockMapEntry_2 = catchHandler_u1.getNested().get(1);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_2, 2, 9, 9, 10, 1);
		// Try 9
		var tryBlock_9 = tryBlockMapEntry_2.getTryBlock();
		assertTryBlockProperties(tryBlock_9, 9, 9, 0);
		// Catch 9+?
		var catchHandler_w = tryBlockMapEntry_2.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_w, -2, 0x004019d2);
		assertEquals(0, catchHandler_w.getNested().size());

		
		// Catch 7+?
		var catchHandler_u2 = tryBlockMapEntry_4.getCatchHandlers().get(1);
		assertCatchHandlerProperties(catchHandler_u2, -2, 0x004019f5);
		assertEquals(2, catchHandler_u2.getNested().size());

		// TryBlockMapEntry [3] #2
		var tryBlockMapEntry_3_2 = catchHandler_u2.getNested().get(0);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_3_2, 3, 11, 11, 12, 1);
		assertEquals(tryBlockMapEntry_3_1, tryBlockMapEntry_3_2);
		// Try 11
		tryBlock_11 = tryBlockMapEntry_3_2.getTryBlock();
		assertTryBlockProperties(tryBlock_11, 11, 11, 0);
		// Catch 11+?
		catchHandler_v = tryBlockMapEntry_3_2.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_v, -2, 0x00401a05);
		assertEquals(0, catchHandler_v.getNested().size());
		// TryBlockMapEntry [2]
		tryBlockMapEntry_2 = catchHandler_u2.getNested().get(1);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_2, 2, 9, 9, 10, 1);
		// Try 9
		tryBlock_9 = tryBlockMapEntry_2.getTryBlock();
		assertTryBlockProperties(tryBlock_9, 9, 9, 0);
		// Catch 9+?
		catchHandler_w = tryBlockMapEntry_2.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_w, -2, 0x004019d2);
		assertEquals(0, catchHandler_w.getNested().size());	
	}

	@Test
	public void testParseFile1() throws IOException {
		var outer = nsp.parseFile(testFile1);
		
		assertEquals(1, outer.size());

		var tryBlockMapEntry_5 = outer.get(0);
		assertEquals(5, tryBlockMapEntry_5.getMapIndex());
		assertEquals(1, tryBlockMapEntry_5.getTryLow());
		assertEquals(5, tryBlockMapEntry_5.getTryHigh());
		assertEquals(12, tryBlockMapEntry_5.getCatchHigh());
		assertEquals(1, tryBlockMapEntry_5.getNCatches());

		var tryBlock_1 = tryBlockMapEntry_5.getTryBlock();
		assertEquals(1, tryBlock_1.getState());
		assertEquals(5, tryBlock_1.getTryHigh());
		assertEquals(1, tryBlock_1.getNested().size());

		var tryBlockMapEntry_1 = tryBlock_1.getNested().get(0);
		assertEquals(1, tryBlockMapEntry_1.getMapIndex());
		assertEquals(2, tryBlockMapEntry_1.getTryLow());
		assertEquals(4, tryBlockMapEntry_1.getTryHigh());
		assertEquals(5, tryBlockMapEntry_1.getCatchHigh());
		assertEquals(1, tryBlockMapEntry_1.getNCatches());

		var tryBlock_2 = tryBlockMapEntry_1.getTryBlock();
		assertEquals(2, tryBlock_2.getState());
		assertEquals(4, tryBlock_2.getTryHigh());
		assertEquals(1, tryBlock_2.getNested().size());

		var tryBlockMapEntry_0 = tryBlock_2.getNested().get(0);
		assertEquals(0, tryBlockMapEntry_0.getMapIndex());
		assertEquals(3, tryBlockMapEntry_0.getTryLow());
		assertEquals(3, tryBlockMapEntry_0.getTryHigh());
		assertEquals(4, tryBlockMapEntry_0.getCatchHigh());
		assertEquals(1, tryBlockMapEntry_0.getNCatches());

		var tryBlock_3 = tryBlockMapEntry_0.getTryBlock();
		assertEquals(3, tryBlock_3.getState());
		assertEquals(3, tryBlock_3.getTryHigh());
		assertEquals(0, tryBlock_3.getNested().size());

		// Catch 3+?
		assertEquals(1, tryBlockMapEntry_0.getCatchHandlers().size());
		var catchHandler_x = tryBlockMapEntry_0.getCatchHandlers().get(0);
		assertEquals(-2, catchHandler_x.getState());
		assertEquals(0x0040196b, Integer.parseInt(catchHandler_x.getAddressString(), 16));
		assertEquals(0, catchHandler_x.getNested().size());

		// Catch 2+?
		assertEquals(1, tryBlockMapEntry_1.getCatchHandlers().size());
		var catchHandler_y = tryBlockMapEntry_1.getCatchHandlers().get(0);
		assertEquals(-2, catchHandler_y.getState());
		assertEquals(0x0040198c, Integer.parseInt(catchHandler_y.getAddressString(), 16));
		assertEquals(0, catchHandler_y.getNested().size());
		
		// Catch 1+?
		assertEquals(1, tryBlockMapEntry_5.getCatchHandlers().size());
		var catchHandler_z = tryBlockMapEntry_5.getCatchHandlers().get(0);
		assertEquals(-2, catchHandler_z.getState());
		assertEquals(0x004019b0, Integer.parseInt(catchHandler_z.getAddressString(), 16));
		assertEquals(1, catchHandler_z.getNested().size());
		
		// TryBlockMapEntry [4]
		var tryBlockMapEntry_4 = catchHandler_z.getNested().get(0);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_4, 4, 7, 7, 12, 2);
		assertEquals(2, tryBlockMapEntry_4.getCatchHandlers().size());

		var tryBlock_7 = tryBlockMapEntry_4.getTryBlock();
		assertTryBlockProperties(tryBlock_7, 7, 7, 0);


		// Catch 7+ #1
		var catchHandler_u1 = tryBlockMapEntry_4.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_u1, -2, 0x004019c2);
		assertEquals(0, catchHandler_u1.getNested().size());

		// Catch 7+ #2
		var catchHandler_u2 = tryBlockMapEntry_4.getCatchHandlers().get(1);
		assertCatchHandlerProperties(catchHandler_u2, -2, 0x004019f5);
		assertEquals(0, catchHandler_u2.getNested().size());

		// Things that remain to be nested.
		assertEquals(2, tryBlockMapEntry_4.getToBeNestedInCatches().size());
			
		// TryBlockMapEntry [3]
		var tryBlockMapEntry_3 = tryBlockMapEntry_4.getToBeNestedInCatches().get(0);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_3, 3, 11, 11, 12, 1);
		// Try 11
		var tryBlock_11 = tryBlockMapEntry_3.getTryBlock();
		assertTryBlockProperties(tryBlock_11, 11, 11, 0);
		assertEquals(0, tryBlock_11.getNested().size());
		// Catch 11+?
		var catchHandler_v = tryBlockMapEntry_3.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_v, -2, 0x00401a05);
		assertEquals(0, catchHandler_v.getNested().size());
		
		// TryBlockMapEntry [2]		
		var tryBlockMapEntry_2 = tryBlockMapEntry_4.getToBeNestedInCatches().get(1);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_2, 2, 9, 9, 10, 1);
		// Try 9
		var tryBlock_9 = tryBlockMapEntry_2.getTryBlock();
		assertTryBlockProperties(tryBlock_9, 9, 9, 0);
		assertEquals(0, tryBlock_9.getNested().size());
		// Catch 9+?
		var catchHandler_w = tryBlockMapEntry_2.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_w, -2, 0x004019d2);
		assertEquals(0, catchHandler_w.getNested().size());
		
	}

	@Test
	public void testParseFile2() throws IOException {
		var outer = nsp.parseFile(testFile2);
		
		assertEquals(3, outer.size());

		var tryBlockMapEntry_0 = outer.get(0);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_0, 0, 0, 0, 1, 1);
		assertEquals(1, tryBlockMapEntry_0.getCatchHandlers().size());

		var tryBlock_0 = tryBlockMapEntry_0.getTryBlock();
		assertTryBlockProperties(tryBlock_0, 0, 0, 0);
		assertEquals(0, tryBlock_0.getNested().size());

		var catchHandler_x = tryBlockMapEntry_0.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_x, -2, 0x004013cc);
		assertEquals(0, catchHandler_x.getNested().size());

		
		var tryBlockMapEntry_1 = outer.get(1);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_1, 1, 2, 2, 3, 1);
		assertEquals(1, tryBlockMapEntry_1.getCatchHandlers().size());

		var tryBlock_2 = tryBlockMapEntry_1.getTryBlock();
		assertTryBlockProperties(tryBlock_2, 2, 2, 0);
		assertEquals(0, tryBlock_2.getNested().size());

		catchHandler_x = tryBlockMapEntry_1.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_x, -2, 0x004013fd);
		assertEquals(0, catchHandler_x.getNested().size());

		
		var tryBlockMapEntry_2 = outer.get(2);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_2, 2, 5, 5, 6, 2);
		assertEquals(2, tryBlockMapEntry_2.getCatchHandlers().size());

		var tryBlock_5 = tryBlockMapEntry_2.getTryBlock();
		assertTryBlockProperties(tryBlock_5, 5, 5, 0);
		assertEquals(0, tryBlock_5.getNested().size());

		catchHandler_x = tryBlockMapEntry_2.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_x, -2, 0x0040148f);
		assertEquals(0, catchHandler_x.getNested().size());
		catchHandler_x = tryBlockMapEntry_2.getCatchHandlers().get(1);
		assertCatchHandlerProperties(catchHandler_x, -2, 0x0040149e);
		assertEquals(0, catchHandler_x.getNested().size());

	}

	@Test
	public void testParseFile2Simple() throws IOException {
		var outer = nsp.parseFile(testFile2Simple);
		
		assertEquals(3, outer.size());

		var tryBlockMapEntry_0 = outer.get(0);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_0, 0, 0, 0, 1, 1);
		assertEquals(1, tryBlockMapEntry_0.getCatchHandlers().size());

		var tryBlock_0 = tryBlockMapEntry_0.getTryBlock();
		assertTryBlockProperties(tryBlock_0, 0, 0, 0);
		assertEquals(0, tryBlock_0.getNested().size());

		var catchHandler_x = tryBlockMapEntry_0.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_x, -2, 0x004013cc);
		assertEquals(0, catchHandler_x.getNested().size());

		
		var tryBlockMapEntry_1 = outer.get(1);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_1, 1, 2, 2, 3, 1);
		assertEquals(1, tryBlockMapEntry_1.getCatchHandlers().size());

		var tryBlock_2 = tryBlockMapEntry_1.getTryBlock();
		assertTryBlockProperties(tryBlock_2, 2, 2, 0);
		assertEquals(0, tryBlock_2.getNested().size());

		catchHandler_x = tryBlockMapEntry_1.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_x, -2, 0x004013fd);
		assertEquals(0, catchHandler_x.getNested().size());

		
		var tryBlockMapEntry_2 = outer.get(2);
		assertTryBlockMapEntryProperties(tryBlockMapEntry_2, 2, 4, 4, 5, 2);
		assertEquals(1, tryBlockMapEntry_2.getCatchHandlers().size());

		var tryBlock_4 = tryBlockMapEntry_2.getTryBlock();
		assertTryBlockProperties(tryBlock_4, 4, 4, 0);
		assertEquals(0, tryBlock_4.getNested().size());

		catchHandler_x = tryBlockMapEntry_2.getCatchHandlers().get(0);
		assertCatchHandlerProperties(catchHandler_x, -2, 0x0040148f);
		assertEquals(0, catchHandler_x.getNested().size());

	}

	private void assertTryBlockMapEntryProperties(TryBlockMapEntry tryBlockMapEntry, int mapIndex, int tryLow, int tryHigh, int catchHigh, int nCatches) {
		assertEquals(mapIndex, tryBlockMapEntry.getMapIndex());
		assertEquals(tryLow, tryBlockMapEntry.getTryLow());
		assertEquals(tryHigh, tryBlockMapEntry.getTryHigh());
		assertEquals(catchHigh, tryBlockMapEntry.getCatchHigh());
		assertEquals(nCatches, tryBlockMapEntry.getNCatches());
	}

	private void assertTryBlockProperties(TryBlock tryBlock, int state, int tryHigh, int nestedSize) {
		assertEquals(state, tryBlock.getState());
		assertEquals(tryHigh, tryBlock.getTryHigh());
		assertEquals(nestedSize, tryBlock.getNested().size());
	}

	private void assertCatchHandlerProperties(CatchHandler catchHandler_x, int state, int address) {
		assertEquals(state, catchHandler_x.getState());
		assertEquals(address, Integer.parseInt(catchHandler_x.getAddressString(), 16));
	}
}
