import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import logging
# === Load model and encoder ===
model = joblib.load("ids_model.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# === Define selected features ===
selected_features = [
    'flag',
    'land',
    'wrong_fragment',
    'logged_in',
    'count',
    'serror_rate',
    'srv_serror_rate',
    'same_srv_rate',
    'dst_host_srv_count',
    'dst_host_same_srv_rate',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate',
    'dst_host_srv_serror_rate',
    
]

# === Session statistics to compute rates ===
stats = defaultdict(lambda: defaultdict(int))

# === Extract features from a packet ===
def extract_features(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return None
    
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    dst_port = packet[TCP].dport
    flags = packet[TCP].flags

    # Update stats
    stats[ip_src]['count'] += 1
    if flags & 0x04:  # TCP RST (reset) flag
        stats[ip_src]['serror'] += 1
        stats[ip_dst]['dst_serror'] += 1
        stats[ip_dst]['dst_srv_serror'] += 1
    
    stats[ip_dst]['dst_host_srv_count'] += 1
    stats[ip_dst][f'srv_{dst_port}'] += 1
    
    # Features
    features = {
        'flag': int(flags),
        'land': 1 if ip_src == ip_dst else 0,
        'wrong_fragment': 1 if packet[IP].flags == 1 else 0,
        'logged_in': 1,  # Simplified (placeholder)
        'count': stats[ip_src]['count'],
        'serror_rate': stats[ip_src]['serror'] / stats[ip_src]['count'] if stats[ip_src]['count'] > 0 else 0,
        'srv_serror_rate': stats[ip_src]['serror'] / stats[ip_src]['count'] if stats[ip_src]['count'] > 0 else 0,
        'same_srv_rate': stats[ip_dst][f'srv_{dst_port}'] / stats[ip_dst]['dst_host_srv_count'] if stats[ip_dst]['dst_host_srv_count'] > 0 else 0,
        'dst_host_srv_count': stats[ip_dst]['dst_host_srv_count'],
        'dst_host_same_srv_rate': stats[ip_dst][f'srv_{dst_port}'] / stats[ip_dst]['dst_host_srv_count'] if stats[ip_dst]['dst_host_srv_count'] > 0 else 0,
        'dst_host_srv_diff_host_rate': (stats[ip_dst]['dst_host_srv_count'] - stats[ip_dst][f'srv_{dst_port}']) / stats[ip_dst]['dst_host_srv_count'] if stats[ip_dst]['dst_host_srv_count'] > 0 else 0,
        'dst_host_serror_rate': stats[ip_dst]['dst_serror'] / stats[ip_dst]['dst_host_srv_count'] if stats[ip_dst]['dst_host_srv_count'] > 0 else 0,
        'dst_host_srv_serror_rate': stats[ip_dst]['dst_srv_serror'] / stats[ip_dst]['dst_host_srv_count'] if stats[ip_dst]['dst_host_srv_count'] > 0 else 0
    }
    return features

# === Callback for each packet ===
logging.basicConfig(filename='intrusion_log.txt', level=logging.INFO)
def process_packet(packet):
    features = extract_features(packet)
    if features:
        df = pd.DataFrame([features])[selected_features]
        prediction_encoded = model.predict(df)[0]
        prediction = label_encoder.inverse_transform([prediction_encoded])[0]
        
        print(f"[{time.ctime()}] Prediction: {prediction} | Src: {packet[IP].src} -> Dst: {packet[IP].dst}")
        
        if prediction != "normal":
            print("⚠️ ALERT: Possible intrusion detected!")
            logging.info(f"{time.ctime()} - ALERT: {prediction} - Src: {packet[IP].src} -> Dst: {packet[IP].dst}")
        time.sleep(0.5)        



# === Start sniffing ===
print("🔍 Starting real-time packet sniffing...")
sniff(prn=process_packet, store=False)
