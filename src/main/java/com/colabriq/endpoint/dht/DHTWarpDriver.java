package com.colabriq.endpoint.dht;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.jena.graph.Triple;
import org.apache.log4j.Logger;

import com.colabriq.endpoint.crypto.key.EncodeableSecretKey;
import com.colabriq.endpoint.crypto.key.EncodeableShareKey;
import com.colabriq.endpoint.dht.backend.DHTBackend;
import com.colabriq.endpoint.dht.share.ShareKeyStore;
import com.colabriq.endpoint.dht.share.ShareKeyStoreException;
import com.colabriq.endpoint.graph.containerized.ContainerPatterns;
import com.colabriq.kpabe.KPABEDecryption;
import com.colabriq.kpabe.KPABEEncryption;
import com.colabriq.kpabe.KPABEException;
import com.colabriq.kpabe.key.KPABEPublicKey;
import com.colabriq.model.Pointer;
import com.colabriq.shared.encode.JSON;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;

/** 
 * Methods that work the Warp (container search indexing).
 */
@Singleton
public class DHTWarpDriver {
	private static final Logger log = Logger.getLogger(DHTWarpDriver.class);
	
	private static final SecureRandom RANDOM;
	
	static {
		try {
			RANDOM = SecureRandom.getInstanceStrong();
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	private final DHTGovernor governor;
	private final DHTBackend backend;
	private final ShareKeyStore keyStore;
	
	@Inject
	public DHTWarpDriver(DHTGovernor governor, DHTBackend backend, ShareKeyStore keyStore) {
		this.governor = governor;
		this.backend = backend;
		this.keyStore = keyStore;
	}
	
	/**
	 * Publish data against a new pattern to the Warp
	 * Data is already on the weft, provide the ID
	 */
	public void publish(String location, String pattern, String policy, EncodeableSecretKey key, Future<DHTWarpPublishResult> future) {
		log.debug("Publishing warp pattern: " + pattern);
			
		try {
			var pointer = new Pointer(key.toEncodedString(), location, RANDOM.nextLong());
			var data = encrypt(pointer, policy);
			
			backend.publishPointer(pattern, data, Future.<Void>future().setHandler(
				result -> {
					log.debug("Published warp pattern: " + pattern);
					
					if (result.succeeded()) {
						future.complete(new DHTWarpPublishResult(pointer, data));
					}
					else {
						future.fail(result.cause());
					}
				}
			));
		}
		catch (KPABEException e) {
			log.error("Encryption Error", e);
			future.fail(e);
		}
	}
	
	/**
	 * Encrypt a pointer using KP-ABE
	 */
	private byte[] encrypt(Pointer pointer, String accessPolicy) throws KPABEException {
		var kpabe = KPABEEncryption.getInstance(keyStore.getCurrentKeyPair());
		return kpabe.encrypt(JSON.encodeToString(pointer), accessPolicy).getBytes();
	}
	
	/**
	 * Search for pointers with a particular triple signature
	 * This will lead to containers with results in them
	 */
	public void search(Triple tuple, Future<Stream<Pointer>> future) {
		log.debug("Searching warp for triple " + tuple);
		
		// look for anyone who's ever shared a key matching these triples with us
		// (possibly more than one) and fetch containers for each of them from the DHT
		
		@SuppressWarnings("rawtypes") // because CompositeFuture isn't genericised properly
		List<Future> creators;
		
		try {
			creators = keyStore
				.getCreators(tuple)
				.distinct()
				.map(creator -> {
					// kick off a search per creator
					var searchFuture = Future.<Stream<Pointer>>future();
					search(creator, tuple, searchFuture);
					return searchFuture;
				})
				.collect(Collectors.toList())
			;
		}
		catch (ShareKeyStoreException e) {
			future.fail(e);
			return;
		}
		
		if (creators.isEmpty()) {
			log.info("No known creators found for tuple");
			future.complete(Stream.<Pointer>empty());
		}
		else {
			// wait for all futures to complete, then return
			CompositeFuture.all(creators).setHandler(results -> {
				if (results.succeeded()) {
					// create a concatenated stream
					Stream<Pointer> stream = Stream.empty();
					
					for (var x = 0; x < results.result().size(); x++) {
						results.result().resultAt(x);
						stream = Stream.concat(results.result().resultAt(x), stream);
					}
					
					future.complete(stream);
				}
				else {
					future.fail(results.cause());
				}
			});
		}
	}
	
	/**
	 * Search for containers by a specific creator
	 */
	private void search(KPABEPublicKey creator, Triple tp, Future<Stream<Pointer>> future) {
		log.debug("Searching warp for " + tp + " from " + creator.toString().substring(0, 10));
		
		governor.checkRevise(tp);
		
		var pattern = ContainerPatterns.forSearch(creator, tp);
		
		// have to process this stream because state is changed
		backend.searchForPointers(pattern, Future.<Stream<byte[]>>future().setHandler(
			results -> {
				if (results.succeeded()) {
					future.complete(
						results.result()
							.map(data -> decrypt(creator, tp, data))
								.filter(Optional::isPresent)
								.map(Optional::get)
					);
				}
				else {
					future.fail(results.cause());
				}
			}
		));
	}
	
	/**
	 * Attempt to decrypt a pointer.
	 * Specify publicKey so we know which keys to try against the data
	 */
	private Optional<Pointer> decrypt(KPABEPublicKey creator, Triple pattern, byte [] data) {
		log.info("Got pointer data for " + pattern + " from " + creator.toString().substring(0, 10) + "...");
		
		try {
			return keyStore.getKeys(creator, pattern) // XXX think about expiry?
				.parallel()
				.map(EncodeableShareKey::toKeyPair)
				.map(keyPair -> {
					try {
						var dec = KPABEDecryption.getInstance();
						var result = dec.decrypt(new String(data), keyPair);
						if (result != null) {
							log.debug("Decrypt success");
						}
						else {
							log.debug("Decrypt failure (this can be normal)");
						}
							
						return result;
					}
					catch (KPABEException | InvalidKeyException e) {
						log.error("Error decrypting pointer", e);
						return null;
					}
				})
				.filter(Objects::nonNull)
				.findFirst()
				.map(json -> JSON.decode(json, Pointer.class))
			;
		}
		catch (ShareKeyStoreException e) {
			log.error(e);
			return Optional.empty();
		}
	}
}
