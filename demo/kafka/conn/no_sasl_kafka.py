from kafka import KafkaConsumer

bootstrap_servers = "ip:9092"

topic_name = "testTopic"

consumer = KafkaConsumer(topic_name, bootstrap_servers=bootstrap_servers,
                         #auto_offset_reset='earliest', auto_offset_reset='latest',
                         enable_auto_commit=True)


for message in consumer:
    print ("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
                                          message.offset, message.key,
                                          message.value.decode('utf-8')))

