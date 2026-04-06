import psutil

def get_open_ports():
    connections = psutil.net_connections()
    return [c.laddr.port for c in connections if c.status == "LISTEN"]