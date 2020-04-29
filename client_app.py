from rdt_receive import Client

client = Client("127.0.0.1", 8080, "test.txt")
client.create_socket()
client.receive()
