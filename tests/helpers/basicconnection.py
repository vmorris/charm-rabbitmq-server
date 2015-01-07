def send(connection):
    channel = connection.channel()
    channel.queue_declare(queue='hello')
    channel.basic_publish(exchange='',
                          routing_key='hello',
                          body='Hello World!')
    return


def receive(connection):

    channel = connection.channel()
    channel.queue_declare(queue='hello')

    received_message = None

    def null_fn():
        pass

    connection.add_timeout(10, null_fn)

    for method_frame, properties, body in channel.consume('hello'):
        received_message = body

    channel.cancel()

    if received_message is None:
        raise Exception('No message received')

    return received_message
