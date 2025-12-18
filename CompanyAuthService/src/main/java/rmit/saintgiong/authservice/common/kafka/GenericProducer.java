package rmit.saintgiong.authservice.common.kafka;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class GenericProducer<T> {

    private KafkaTemplate<String, T> kafkaTemplate;

    public void sendMessage(String topic, T message) {
        kafkaTemplate.send(topic, message);
    }

}
