package com.goodforgoodbusiness.endpoint.graph.persistent.rocks.store;

import static com.goodforgoodbusiness.endpoint.graph.persistent.rocks.store.PrefixPattern.startsWith;

import java.util.Iterator;

import org.rocksdb.RocksIterator;

import com.goodforgoodbusiness.shared.TimingRecorder;
import com.goodforgoodbusiness.shared.TimingRecorder.TimingCategory;

/**
 * Iterates over a particular RocksDB prefix.
 * @author ijmad
 */
public class PrefixIterator implements Iterator<byte[]> {
	private final RocksIterator it;
	private final byte[] prefix;
	
	private byte[] curVal = null;
	
	public PrefixIterator(RocksIterator it, byte [] prefix) {
		this.it = it;	
		this.prefix = prefix;
		
		try (var timer = TimingRecorder.timer(TimingCategory.RDF_DATABASE)) {
			if (prefix != null) {
				it.seek(prefix);
			}
			else {
				it.seekToFirst();
			}
		}
		
		updateCurrent();
	}
	
	public PrefixIterator(RocksIterator it) {
		this(it, null);
	}
	
	private void updateCurrent() {
		try (var timer = TimingRecorder.timer(TimingCategory.RDF_DATABASE)) {
			if (it.isValid() && (prefix == null || startsWith(it.key(), prefix))) {
				curVal = it.value();
			}
			else {
				curVal = null;
			}
		}
	}
	
	@Override
	public boolean hasNext() {
		return curVal != null;
	}

	@Override
	public byte[] next() {
		var lastVal = curVal;
		
		it.next();
		updateCurrent();
		
		return lastVal;
	}

	public void close() {
		it.close();
	}
}
