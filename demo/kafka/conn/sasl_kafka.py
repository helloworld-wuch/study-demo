from kafka import KafkaConsumer
import ssl

bootstrap_servers = "ip:9092"
username = "username"
password = "password"

topic_name = "testTopic"

security_protocol = "SASL_PLAINTEXT"
sasl_mechanism = "PLAIN"
ssl_context = ssl.create_default_context()

consumer = KafkaConsumer(topic_name, bootstrap_servers=bootstrap_servers,
                         security_protocol=security_protocol,
                         sasl_plain_username=username,
                         sasl_plain_password=password,
                         sasl_mechanism=sasl_mechanism,
                         #auto_offset_reset='earliest', auto_offset_reset='latest',
                         ssl_context=ssl_context)

for message in consumer:
    print ("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
                                          message.offset, message.key,
                                          message.value.decode('utf-8')))
