package rmit.saintgiong.authservice.common.kafka;

import io.confluent.kafka.serializers.KafkaAvroDeserializer;
import io.confluent.kafka.serializers.KafkaAvroDeserializerConfig;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.listener.ConcurrentMessageListenerContainer;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.requestreply.ReplyingKafkaTemplate;
import rmit.saintgiong.authapi.internal.common.type.KafkaTopic;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableKafka
public class KafkaConsumerConfig {

    @Value("${kafka.kafka-host-url}")
    private String kafkaHostUrl;

    @Value("${kafka.schema-registry-host-url}")
    private String schemaRegistryHostUrl;
    
    @Bean
    public ConsumerFactory<String, Object> authConsumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaHostUrl);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "auth-service-consumer-group");
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, KafkaAvroDeserializer.class);

        // Config Schema Registry
        props.put("schema.registry.url", schemaRegistryHostUrl);

        // 6. CỰC KỲ QUAN TRỌNG: Dòng này bảo nó map về đúng class Java (BirdAvro)
        // Nếu thiếu dòng này, nó sẽ trả về GenericRecord và lại gây lỗi khác.
        props.put(KafkaAvroDeserializerConfig.SPECIFIC_AVRO_READER_CONFIG, true);

        // 7. Cho phép đọc từ đầu nếu không tìm thấy offset (tránh lỗi offset out of range)
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        
        return new DefaultKafkaConsumerFactory<>(props);
    }
    
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> authKafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(authConsumerFactory());
        return factory;
    }

    @Bean
    public ConcurrentMessageListenerContainer<String, Object> replyContainer(ConsumerFactory<String, Object> consumerFactory) {
        ContainerProperties containerProperties = new ContainerProperties(KafkaTopic.COMPANY_REGISTRATION_REPLY_TOPIC);
        containerProperties.setGroupId("auth-service-reply-group");

        return new ConcurrentMessageListenerContainer<>(consumerFactory, containerProperties);
    }

    @Bean
    public ReplyingKafkaTemplate<String, Object, Object> replyingKafkaTemplate(
            ProducerFactory<String, Object> pf,
            ConcurrentMessageListenerContainer<String, Object> replyContainer) {

        return new ReplyingKafkaTemplate<>(pf, replyContainer);
    }
}
