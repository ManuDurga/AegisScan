import socket
def scan_ports(target_ip,ports,timeout=1.2):
    open_ports=[]
    for port in ports:
        s= None 
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(timeout)
            connection_status=s.connect_ex((target_ip,port))#value
            if connection_status==0:
                open_ports.append(port)
        except socket.gaierror:
            return open_ports
        except socket.error:
            continue#KeyboardInterrupt to be handled by main.py
        finally:
            if s:
                s.close()
    return open_ports

def parse_ports(ports_input):
    ports=set()
    if len(ports_input)!=0:
        port_tokens=ports_input.split(',')#converting "1,2,3" to "1","2","3" and "4-7" to "4","5","6","7"
        for i in port_tokens:
            if '-' in i:
                st_end = i.split('-')
                if(len(st_end)==2 and st_end[0].isdigit() and st_end[1].isdigit()):
                    st=int(st_end[0])
                    end=int(st_end[1])
                    if st > end:
                            raise ValueError("Invalid port range")
                    ports.update(range(st,end+1))
                else:
                    raise ValueError("Invalid port format")
            else:
                if i.isdigit() and int(i)<65536:
                    ports.add(int(i))
                else:
                    raise ValueError("Invalid port value")
    return sorted(ports)

scan_ports(target,ports)
