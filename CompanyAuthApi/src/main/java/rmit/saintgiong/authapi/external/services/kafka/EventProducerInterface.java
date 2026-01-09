package rmit.saintgiong.authapi.external.services.kafka;

import java.util.concurrent.ExecutionException;

public interface EventProducerInterface {

    void send(String requestTopic, Object requestData);

    <T> T sendAndReceive(
            String requestTopic,
            String responseTopic,
            Object requestData,
            Class<T> responseType
    ) throws ExecutionException, InterruptedException;
}
