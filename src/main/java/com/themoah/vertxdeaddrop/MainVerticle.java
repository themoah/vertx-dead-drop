package com.themoah.vertxdeaddrop;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.eventbus.MessageConsumer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.LocalMap;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MainVerticle extends AbstractVerticle {

  final int cores = Runtime.getRuntime().availableProcessors();
  private static final Logger log = LoggerFactory.getLogger(MainVerticle.class);
  LocalMap<String, String> kv;
  MessageConsumer<String> encryptionHandler;
  MessageConsumer<String> dataStorage;
  MessageConsumer<String> decryptionHandler;
  MessageConsumer<String> dataRetrieval;



  @Override
  public void start(Promise<Void> startPromise) throws Exception {
    Vertx vertx = Vertx.vertx(new VertxOptions().setWorkerPoolSize(cores/2));

    // in-memory, data is lost after a restart
    kv = vertx.sharedData().getLocalMap("kv");

    Router router = Router.router(vertx);
    router.route().handler(BodyHandler.create());

    healthCheckRegister();
    createMessageHandlers();

    router.get("/").handler(rc -> rc.response().end("Hello from Vert.x!"));
    router.get("/healthz").handler(this::healthCheckHandler);
    // encrypt -> handler -> encrypt the message -> store it
    router.post("/encrypt").handler(this::cryptHandler);
    router.post("/decrypt").handler(this::cryptHandler);
    router.get("/size").handler(this::kvSize);
    // should be always last as it's catch-all
    router.get("/:name").handler(this::extendedHello);

    vertx.createHttpServer()
      .requestHandler(router)
      .listen(8888, http -> {
      if (http.succeeded()) {
        startPromise.complete();
        log.info("HTTP server started on port 8888");
      } else {
        startPromise.fail(http.cause());
      }
    });
  }

  private void extendedHello(RoutingContext rc){
    String message = "hello " + rc.pathParam("name");

    JsonObject jsonObject = new JsonObject().put("message", message);
    vertx.eventBus().publish("address", "hello");

    rc.response()
      .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
      .end(jsonObject.encode());
  }

  private void kvSize(RoutingContext rc){
    Long kvLength = kv.keySet().stream().count();
    rc.response()
      .end("length is " + kvLength.toString());
  }

  private void healthCheckHandler(RoutingContext rc){
    vertx.eventBus()
      .request("healthz", "" )
      .onComplete(reply -> {
        if (reply.succeeded()){
          rc.response()
            .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .end(reply.result().body().toString());
        }
      });
  }

  private void healthCheckRegister(){
    vertx.eventBus().consumer("healthz", message -> {
      JsonObject jsonObject = new JsonObject().put("Status", "ok");
      message.reply(jsonObject.encode());
    });
  }

  private void createMessageHandlers(){
    encryptionHandler = vertx.eventBus().consumer("data.encryption");
    encryptionHandler.handler(message -> {
      log.info("Encrypting the message");
      AESEncryption.EncryptionResult t1 = AESEncryption.encrypt(message.body());
      JsonObject response = new JsonObject()
        .put("encryption.key", t1.getEncryptionKey())
        .put("encrypted.value", t1.getEncryptedValue());
      message.reply(response.encode());
    });

    dataStorage = vertx.eventBus().consumer("data.storage");
    dataStorage.handler(message -> {
      String storageKey;
      log.info("Storing the message");
      JsonObject data = new JsonObject(message.body());
      String value = data.getString("encrypted.value");

      if (value.length() > 8 ){
        storageKey = value.substring(0,7);
      } else {
        storageKey = value;
      }

      log.info("Storing encrypted value with key " + storageKey);
      kv.put(storageKey, value);
      JsonObject jsonObject = new JsonObject()
        .put("retrieval.key", storageKey)
        .put("encryption.key", data.getString("encryption.key"));
      message.reply(jsonObject.encode());
    });

    //
    dataRetrieval = vertx.eventBus().consumer("data.retrieval");
    dataRetrieval.handler(message -> {
      JsonObject jsonObject = new JsonObject(message.body());
      String encryptionKey = jsonObject.getString("encryption.key");
      String retrievalKey = jsonObject.getString("retrieval.key");
      log.info("Trying to retrieve key " + retrievalKey);
      String encryptedValue = kv.get(retrievalKey);
      JsonObject encryptedPair = new JsonObject()
        .put("encryption.key", encryptionKey)
        .put("encrypted.value", encryptedValue);

      // it's a dead-drop, shouldn't be available after retrieval.
      kv.remove(encryptionKey);
      message.reply(encryptedPair.encode());
    });

    decryptionHandler = vertx.eventBus().consumer("data.decryption");
    decryptionHandler.handler(message -> {
      String decryptedValue;
      log.info("Decrypting");
      JsonObject pair = new JsonObject(message.body());
      try{
        decryptedValue = AESEncryption.decrypt(pair.getString("encrypted.value"), pair.getString("encryption.key"));
      } catch (Exception ex){
        log.info("Failed to decrypt");
        decryptedValue = null;
      }
      message.reply(decryptedValue);
    });
  }

  private void cryptHandler(RoutingContext rc){
    String firstAction = "data.retrieval";
    String secondAction;

    if (rc.currentRoute().toString().contains("encrypt")){
      firstAction = "data.encryption";
      secondAction = "data.storage";
    } else {
      // can't have non-final in lambda
      secondAction = "data.decryption";
    }

    String message = rc.body().asString();
    log.info("starting " + firstAction);
    vertx.eventBus()
      .request(firstAction, message)
      .onComplete(ar -> {
          if (ar.succeeded()){
            log.info("starting " + secondAction);
            vertx.eventBus()
              .request(secondAction, ar.result().body())
              .onComplete(ad ->{
                if (ad.succeeded()) {
                  rc.response().end(ad.result().body().toString());
                }
              });
          }
        });
  }
}
