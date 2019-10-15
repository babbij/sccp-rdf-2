package com.colabriq.endpoint.dht;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.jena.graph.Triple;
import org.apache.log4j.Logger;

import com.colabriq.endpoint.crypto.EncryptionException;
import com.colabriq.endpoint.crypto.key.EncodeableSecretKey;
import com.colabriq.endpoint.dht.share.ShareKeyStore;
import com.colabriq.endpoint.graph.containerized.ContainerAttributes;
import com.colabriq.endpoint.graph.containerized.ContainerPatterns;
import com.colabriq.endpoint.storage.TripleContext.Type;
import com.colabriq.endpoint.storage.TripleContexts;
import com.colabriq.model.Pointer;
import com.colabriq.model.StorableContainer;
import com.google.inject.Inject;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;

/**
 * Just a holder around some of the DHT components
 * @author ijmad
 */
public class DHT {
	private static final Logger log = Logger.getLogger(DHT.class);
	
	private final TripleContexts contexts;
	private final DHTWarpDriver warp;
	private final DHTWeftDriver weft;
	private final ShareKeyStore keyStore;
	
	@Inject
	public DHT(TripleContexts contexts, DHTWeftDriver weft, DHTWarpDriver warp, ShareKeyStore keyStore) {
		this.contexts = contexts;
		this.weft = weft;
		this.warp = warp;
		this.keyStore = keyStore;
	}
	
	/**
	 * Publish a container to the weft (storage) and warp (indexing)
	 */
	public void publish(StorableContainer container, Future<Void> future) throws EncryptionException {
		log.debug("Publishing container: " + container.getId());
		
		if (log.isDebugEnabled()) {
			log.debug("Container " + container.getId() + " contains " + container.getTriples().count() + " triples");
		}
		
		// encrypt with secret key + publish to weft
		weft.publish(
			container,
			Future.<DHTWeftPublishResult>future().setHandler(weftPublishResult -> {
				if (weftPublishResult.succeeded()) {
					// record context for all the triples
					container.getTriples().forEach(triple ->
						contexts.create(triple)
							.withType(Type.CONTAINER)
							.withContainerID(container.getId())
							.save()
					);
					
					var key = weftPublishResult.result().getKey();
					
					// pointer should be encrypted with _all_ the possible patterns + other attributes
					var attributes = ContainerAttributes.forPublish(
						keyStore.getCurrentKeyPair().getPublic(),
						container.getTriples()
					);
					
					// patterns to publish are all possible triple combinations
					// create + publish a pointer for each generated pattern
					var patterns = container.getTriples()
						.flatMap(t -> ContainerPatterns.forPublish(keyStore.getCurrentKeyPair().getPublic(), t))
					;
					
					// async publish, collect futures
					@SuppressWarnings("rawtypes")
					var wpfs = new ArrayList<Future>(); 
					
					patterns.forEach(pattern -> {
						var wpf = Future.<DHTWarpPublishResult>future();
						warp.publish(weftPublishResult.result().getPublishedLocation(), pattern, attributes, key, wpf);
						wpfs.add(wpf);
					});
					
					if (wpfs.isEmpty()) {
						future.complete();
					}
					else {
						// success iff they all succeed
						CompositeFuture.all(wpfs)
							.setHandler(cfResult -> {
								if (cfResult.succeeded()) {
									future.complete();
								}
								else {
									future.fail(cfResult.cause());
								}
							});
					}
				}
				else {
					future.fail(weftPublishResult.cause());
				}
			})
		);
	}
	
	/**
	 * Search the warp + weft for a triple pattern
	 */
	public void search(Triple tuple, Future<Stream<StorableContainer>> future) {
		if (log.isDebugEnabled()) {
			log.debug("Searching DHT for " + tuple);
		}

		// process the stream because these operations have side effects
		warp.search(tuple, Future.<Stream<Pointer>>future().setHandler(
			warpResults -> {
				if (warpResults.succeeded()) {
					@SuppressWarnings("rawtypes") // CompositeFuture's generics are broken
					List<Future> fetchFutures = 
						warpResults.result()
							.map(ptr -> {
								// fetch from warp, collect futures
								var fetchFuture = Future.<Optional<StorableContainer>>future();
								
								weft.fetch(
									ptr.getContainerLocation(),
									new EncodeableSecretKey(ptr.getContainerKey()),
									fetchFuture
								);
								
								return fetchFuture;
							})
							.collect(Collectors.toList())
					;
					
					if (fetchFutures.isEmpty()) {
						future.complete(Stream.empty());
					}
					else {
						// wait for futures, process results
						CompositeFuture.all(fetchFutures).setHandler(fetchResults -> {
							var containers = new ArrayList<StorableContainer>(fetchFutures.size());
							
							if (fetchResults.succeeded()) {
								for (var x = 0; x < fetchResults.result().size(); x++) {
									Optional<StorableContainer> container = fetchResults.result().resultAt(x);
									if (container.isPresent()) {
										containers.add(container.get());
									}
								}
								
								if (log.isDebugEnabled()) {
									log.debug("Containers found = " + containers.size());
								}
								
								// return containers we've found
								future.complete(containers.parallelStream());
							}
							else {
								future.fail(fetchResults.cause());
							}
						});
					}
				}
				else {
					future.fail(warpResults.cause());
				}
			}
		));
	}
}
