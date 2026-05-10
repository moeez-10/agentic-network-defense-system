import time
from detection.anomaly_engine import AnomalyEngine

engine = AnomalyEngine(
    rate_window_sec=3,
    rate_threshold=5,          # low threshold so it triggers quickly in test
    payload_size_threshold=100,
    portscan_window_sec=10,
    portscan_unique_ports=5,
)

base = {
    "src_ip": "10.0.0.8",
    "dst_ip": "10.0.0.20",
    "protocol": "TCP",
    "src_port": 11111,
    "packet_length": 120,
    "payload": b"abc",
    "payload_len": 3,
    "layer7_type": "UNKNOWN",
}

print("=== Test 1: Rate anomaly ===")
for i in range(7):
    pkt = dict(base)
    pkt["dst_port"] = 80
    alerts = engine.check(pkt)
    for a in alerts:
        print(engine.format_alert(a))
    time.sleep(0.2)
engine = AnomalyEngine(rate_window_sec=3, rate_threshold=5, payload_size_threshold=100, portscan_window_sec=10, portscan_unique_ports=5)
print("\n=== Test 2: Payload size anomaly ===")
pkt2 = dict(base)
pkt2["dst_port"] = 80
pkt2["payload_len"] = 500  # exceeds threshold=100
alerts = engine.check(pkt2)
for a in alerts:
    print(engine.format_alert(a))
engine = AnomalyEngine(rate_window_sec=3, rate_threshold=5, payload_size_threshold=100, portscan_window_sec=10, portscan_unique_ports=5)
print("\n=== Test 3: Port scan anomaly ===")
for port in [21, 22, 23, 80, 443, 3389]:
    pkt3 = dict(base)
    pkt3["dst_port"] = port
    alerts = engine.check(pkt3)
    for a in alerts:
        print(engine.format_alert(a))
    time.sleep(0.1)