from app.rpc.rpc_server import RpcServer
import configparser


if __name__ == "__main__":

    config = configparser.ConfigParser()
    config.read("rpc.conf")

    rpc_host = config.get('server', 'rpc_host')
    rpc_port = config.get('server', 'rpc_port')




    server = RpcServer(rpc_host, int(rpc_port))
    server.serve_forever()