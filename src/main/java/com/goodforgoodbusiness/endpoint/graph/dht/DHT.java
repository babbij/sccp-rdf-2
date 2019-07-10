package com.goodforgoodbusiness.endpoint.graph.dht;

import java.util.ArrayList;

import org.apache.log4j.Logger;

import com.goodforgoodbusiness.endpoint.ShareManager;
import com.goodforgoodbusiness.endpoint.crypto.EncryptionException;
import com.goodforgoodbusiness.endpoint.graph.persistent.TripleContexts;
import com.goodforgoodbusiness.endpoint.graph.persistent.TripleContext.Type;
import com.goodforgoodbusiness.endpoint.graph.persistent.container.ContainerAttributes;
import com.goodforgoodbusiness.endpoint.graph.persistent.container.ContainerPatterns;
import com.goodforgoodbusiness.model.StorableContainer;
import com.goodforgoodbusiness.model.TriTuple;
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
	private final ShareManager keyManager;
	
	@Inject
	public DHT(TripleContexts contexts, DHTWeftDriver weft, DHTWarpDriver warp, ShareManager keyManager) {
		this.contexts = contexts;
		this.weft = weft;
		this.warp = warp;
		this.keyManager = keyManager;
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
			Future.<DHTWeftPublish>future().setHandler(weftPublishResult -> {
				if (weftPublishResult.succeeded()) {
					// record context for all the triples
					container.getTriples().forEach(triple ->
						contexts.create(triple)
							.withType(Type.CONTAINER_ID)
							.withContainerID(container.getId())
							.save()
					);
					
					var key = weftPublishResult.result().getKey();
					
					// pointer should be encrypted with _all_ the possible patterns + other attributes
					var attributes = ContainerAttributes.forPublish(
						keyManager.getCreatorKey(),
						container.getTriples().map(t -> TriTuple.from(t))
					);
						
					// patterns to publish are all possible triple combinations
					// create + publish a pointer for each generated pattern
					var patterns = container.getTriples()
						.flatMap(t -> ContainerPatterns.forPublish(keyManager, TriTuple.from(t)))
					;
					
					// async publish, collect futures
					@SuppressWarnings("rawtypes")
					var wpfs = new ArrayList<Future>(); 
					
					patterns.forEach(pattern -> {
						var wpf = Future.<DHTWarpPublish>future();
						warp.publish(container.getId(), pattern, attributes, key, wpf);
						wpfs.add(wpf);
					});
					
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
				else {
					future.fail(weftPublishResult.cause());
				}
			})
		);
	}
}