package rmit.saintgiong.authservice.common.kafka;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.ConcurrentMessageListenerContainer;
import org.springframework.kafka.listener.ContainerProperties;
import rmit.saintgiong.shared.type.KafkaTopic;

@Configuration
@EnableKafka
public class KafkaConsumerConfig {

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory(
            KafkaTemplate<String, Object> kafkaTemplate,
            ConsumerFactory<String, Object> consumerFactory
    ) {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setReplyTemplate(kafkaTemplate);
        factory.setConsumerFactory(consumerFactory);
        return factory;
    }

    @Bean
    public ConcurrentMessageListenerContainer<String, Object> replyListenerContainer(
            ConsumerFactory<String, Object> consumerFactory
    ) {
        // Topic for request and reply communication
        ContainerProperties containerProperties = new ContainerProperties(
                KafkaTopic.JM_CREATE_PROFILE_RESPONSE_TOPIC,
                KafkaTopic.JM_CREATE_SUBSCRIPTION_RESPONSE_TOPIC
        );

        return new ConcurrentMessageListenerContainer<>(consumerFactory, containerProperties);
    }
}
