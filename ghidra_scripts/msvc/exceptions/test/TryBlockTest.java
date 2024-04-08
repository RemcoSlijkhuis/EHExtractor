package msvc.exceptions.test;
import msvc.exceptions.src.*;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class TryBlockTest {

	protected TryBlock tryBlock_0_10;
	protected TryBlock tryBlock_1_2;
	
	@Before
	public void setUp() {
		int tryLow = 0;
		int tryHigh = 10;
		tryBlock_0_10 = new TryBlock(tryLow, tryHigh);

		tryLow = 1;
		tryHigh = 2;
		tryBlock_1_2 = new TryBlock(tryLow, tryHigh);
	}

	@Test
	public void testGetBlockType() {
		assertEquals(BlockType.TRY, tryBlock_0_10.getBlockType());
	}

	@Test
	public void testStateZero() {
		assertEquals(0, tryBlock_0_10.getState());
	}

	@Test
	public void testStateNotZero() {
		assertEquals(1, tryBlock_1_2.getState());
	}

	@Test
	public void testValidStateTrue1() {
		assertTrue(tryBlock_0_10.hasValidState());
	}

	@Test
	public void testValidStateTrue2() {
		int tryLow = -1;
		int tryHigh = 10;
		var tryBlockLowestState = new TryBlock(tryLow, tryHigh);
		
		assertTrue(tryBlockLowestState.hasValidState());
	}

	@Test
	public void testValidStateFalse() {
		int tryLow = -2;
		int tryHigh = 10;
		var tryBlockInvalidState = new TryBlock(tryLow, tryHigh);
		
		assertFalse(tryBlockInvalidState.hasValidState());
	}

	@Test()
	public void testSetStateOk() {
		int curState = tryBlock_0_10.getState();
		tryBlock_0_10.setState(curState);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetStateException1() {
		int curState = tryBlock_0_10.getState();
		tryBlock_0_10.setState(curState+1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetStateException2() {
		int curState = tryBlock_0_10.getState();
		tryBlock_0_10.setState(curState-1);
	}
	
	@Test
	public void testNestSizeOk() {
		TryBlockMapEntry tryBlockMapEntry = new TryBlockMapEntry(1, 2, 3, 4, 5, null, tryBlock_0_10, null);
		tryBlock_0_10.nest(tryBlockMapEntry);
		assertEquals(1, tryBlock_0_10.getNested().size());

		tryBlock_0_10.nest(tryBlockMapEntry);
		assertEquals(2, tryBlock_0_10.getNested().size());
	}

	@Test
	public void testNestedEmpty() {
		assertEquals(0, tryBlock_0_10.getNested().size());
	}

}
