from rdt_send import Server

server = Server()
status = server.connect()
if status:
    server.run()