package msvc.exceptions;

import java.util.Comparator;

class TryLowComparator implements Comparator<TryBlockMapEntry> {
	@Override
	public int compare(TryBlockMapEntry entry1, TryBlockMapEntry entry2) {
		return Integer.compare(entry1.getTryLow(), entry2.getTryLow());
	}
}