from detection.signature_engine import SignatureEngine

engine = SignatureEngine("detection/rules.json")

# Fake packet record similar to Day 6 output
packet_record = {
    "timestamp": "TEST",
    "src_ip": "10.0.0.5",
    "dst_ip": "10.0.0.10",
    "protocol": "TCP",
    "src_port": 12345,
    "dst_port": 80,
    "packet_length": 100,
    "payload": b"GET /search?q=1' OR 1=1 -- HTTP/1.1\r\nHost: test\r\n\r\n",
    "payload_len": 60,
    "layer7_type": "HTTP",
}

alerts = engine.check(packet_record)

print(f"Alerts returned: {len(alerts)}")
for a in alerts:
    print(engine.format_alert(a))