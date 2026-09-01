import socket


def grab_banner(target_ip, port, timeout=2):
    """
    Attempts to retrieve information exposed by a service
    running on an open TCP port.
    """

    s = None

    try:
        # Create a TCP socket
        s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )

        # Prevent the program from waiting indefinitely
        s.settimeout(timeout)

        # Connect to the already identified open port
        s.connect((target_ip, port))

        # Attempt to receive data sent by the service
        banner = s.recv(1024)

        # Convert received bytes into readable text
        return banner.decode(
            "utf-8",
            errors="replace"
        ).strip()

    except socket.timeout:
        return None

    except socket.error:
        return None

    finally:
        if s:
            s.close()
