package msvc.exceptions;

import java.util.Comparator;

/**
 * A comparator for TryBlockMapEntry objects, using the tryLow values.
 */
class TryLowComparator implements Comparator<TryBlockMapEntry> {
    /**
     * Compares two TryBlockMapEntry objects by their tryLow values.
     *
     * @param entry1 The first TryBlockMapEntry.
     * @param entry2 The second TryBlockMapEntry.
     * @return < 0 if the first tryLow value is less than the second, 0 if they are equal, > 0 if the first is greater than the second.
     */
	@Override
	public int compare(TryBlockMapEntry entry1, TryBlockMapEntry entry2) {
		return Integer.compare(entry1.getTryLow(), entry2.getTryLow());
	}
}