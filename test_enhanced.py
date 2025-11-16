from scapy.all import *
import time

print("Testing Enhanced IDS...")

# Test 1: Suspicious port
send(IP(dst="127.0.0.1")/TCP(dport=31337, flags="S"), verbose=0)
print("✅ Sent suspicious port connection")

# Test 2: Malicious payload
malicious_payload = b"exec(base64_decode('test'))"
send(IP(dst="127.0.0.1")/TCP(dport=80)/Raw(load=malicious_payload), verbose=0)
print("✅ Sent malicious payload")

# Test 3: Port scan
for port in [10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010, 10011, 10012, 10013, 10014, 10015]:
    send(IP(dst="127.0.0.1")/TCP(dport=port, flags="S"), verbose=0)
    time.sleep(0.1)

print("✅ Sent port scan simulation")
print("Check your IDS for enhanced alerts!")