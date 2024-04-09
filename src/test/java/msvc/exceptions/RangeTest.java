package msvc.exceptions;

import static org.junit.Assert.*;
import org.junit.Test;

import msvc.exceptions.*;

public class RangeTest {

	@Test
	public void testRangeT() {
		var rangeInteger = new Range<Integer>(1, 10);
		var rangeString = new Range<String>("min", "max");
	}

	@Test
	public void testContainsT() {
		var range = new Range<Integer>(1, 10);
		assertTrue(range.contains(5));
	}

	@Test
	public void testNotContainsT() {
		var range = new Range<Integer>(1, 10);
		assertFalse(range.contains(20));
	}

	@Test
	public void testContainsRangeOfT() {
		var range1 = new Range<Integer>(-10, 100);
		var range2 = new Range<Integer>(1, 10);
		assertTrue(range1.contains(range2));
	}

	@Test
	public void testNotContainsRangeOfT() {
		var range1 = new Range<Integer>(-10, 100);
		var range2 = new Range<Integer>(1, 10);
		assertFalse(range2.contains(range1));
	}

}
