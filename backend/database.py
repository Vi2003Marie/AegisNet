import pymysql
import pymysql.cursors

def get_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='123',
        database='aegisnet',
        charset='utf8',
        cursorclass=pymysql.cursors.DictCursor
    )

def log_packet(src_ip, dst_ip, protocol, packet_size):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO network_logs (src_ip, dst_ip, protocol, packet_size) VALUES (%s, %s, %s, %s)",
            (src_ip, dst_ip, protocol, packet_size)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] log_packet: {e}")

def log_device(ip_address, mac_address):
    try:
        import socket
        import nmap

        device_name = 'Unknown'

        # Try reverse DNS first
        try:
            device_name = socket.gethostbyaddr(ip_address)[0]
        except:
            pass

        # If still unknown try nmap
        if device_name == 'Unknown':
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=ip_address, arguments='-sn')
                if ip_address in nm.all_hosts():
                    hostnames = nm[ip_address].hostnames()
                    if hostnames and hostnames[0]['name']:
                        device_name = hostnames[0]['name']
            except:
                pass

        # If still unknown try NetBIOS style
        if device_name == 'Unknown':
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=ip_address, arguments='-sU --script nbstat.nse -p137')
                if ip_address in nm.all_hosts():
                    if 'hostscript' in nm[ip_address]:
                        for script in nm[ip_address]['hostscript']:
                            if 'nbstat' in script['id']:
                                device_name = script['output'].split('\n')[0].strip()
            except:
                pass

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM connected_devices WHERE ip_address = %s",
            (ip_address,)
        )
        existing = cursor.fetchone()
        if not existing:
            cursor.execute(
                "INSERT INTO connected_devices (ip_address, mac_address, device_name) VALUES (%s, %s, %s)",
                (ip_address, mac_address, device_name)
            )
        else:
            cursor.execute(
                "UPDATE connected_devices SET device_name = %s, last_seen = NOW() WHERE ip_address = %s",
                (device_name, ip_address)
            )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[DEVICE] {ip_address} - {mac_address} - {device_name}")
    except Exception as e:
        print(f"[DB ERROR] log_device: {e}")

def log_alert(alert_type, src_ip, description, severity):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (alert_type, src_ip, description, severity) VALUES (%s, %s, %s, %s)",
            (alert_type, src_ip, description, severity)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] log_alert: {e}")

def block_ip(ip_address, reason):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT IGNORE INTO blocked_ips (ip_address, reason) VALUES (%s, %s)",
            (ip_address, reason)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[BLOCKED] {ip_address} - {reason}")

        # Block IP in Windows Firewall
        import subprocess
        rule_name = f"AegisNet_Block_{ip_address}"
        subprocess.run([
            'netsh', 'adv firewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            'dir=in',
            'action=block',
            f'remoteip={ip_address}',
            'enable=yes'
        ], capture_output=True)
        subprocess.run([
            'netsh', 'adv firewall', 'firewall', 'add', 'rule',
            f'name={rule_name}_out',
            'dir=out',
            'action=block',
            f'remoteip={ip_address}',
            'enable=yes'
        ], capture_output=True)
        print(f"[FIREWALL] Blocked {ip_address} in Windows Firewall")


    except Exception as e:
        print(f"[DB ERROR] block_ip: {e}")

def get_blocked_ips():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    except Exception as e:
        print(f"[DB ERROR] get_blocked_ips: {e}")
        return []

def unblock_ip(ip_address):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (ip_address,))
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[UNBLOCKED] {ip_address}")

        # Remove firewall rule
        import subprocess
        rule_name = f"AegisNet_Block_{ip_address}"
        subprocess.run([
            'netsh', 'adv firewall', 'firewall', 'delete', 'rule',
            f'name={rule_name}'
        ], capture_output=True)
        subprocess.run([
            'netsh', 'adv firewall', 'firewall', 'delete', 'rule',
            f'name={rule_name}_out'
        ], capture_output=True)
        print(f"[FIREWALL] Removed firewall rule for {ip_address}")

    except Exception as e:
        print(f"[DB ERROR] unblock_ip: {e}")

    def arp_block(ip_address):
        import threading
        t = threading.Thread(target=_arp_poison, args=(ip_address,), daemon=True)
        t.start()

def _arp_poison(target_ip):
    from scapy.all import ARP, send, getmacbyip
    import time
    import subprocess

    # Get gateway IP using ipconfig
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        gateway_ip = None
        for line in result.stdout.split('\n'):
            if 'Default Gateway' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    gw = parts[1].strip()
                    if gw and gw != '':
                        gateway_ip = gw
                        break
    except Exception as e:
        print(f"[ARP ERROR] Could not get gateway: {e}")
        return

    if not gateway_ip:
        print(f"[ARP ERROR] Could not find gateway IP")
        return

    print(f"[ARP] Starting ARP block on {target_ip}, gateway is {gateway_ip}")
    target_mac = getmacbyip(target_ip)

    if not target_mac:
        print(f"[ARP ERROR] Could not find MAC for {target_ip}")
        return

    try:
        while True:
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            time.sleep(1)

            from database import get_blocked_ips
            blocked = [b['ip_address'] for b in get_blocked_ips()]
            if target_ip not in blocked:
                print(f"[ARP] Stopping ARP block on {target_ip}")
                break
    except Exception as e:
        print(f"[ARP ERROR] {e}")

def get_all_users():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    except Exception as e:
        print(f"[DB ERROR] get_all_users: {e}")
        return []

def add_user(username, password, role):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            (username, password, role)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] add_user: {e}")
        return False

def delete_user(user_id):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB ERROR] delete_user: {e}")
        return False

def verify_user(username, password):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = %s AND password = %s",
            (username, password)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user
    except Exception as e:
        print(f"[DB ERROR] verify_user: {e}")
        return None