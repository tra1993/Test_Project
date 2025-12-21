import sys
import json
import re
import os
from datetime import datetime

# Packet ဖတ်ရန်အတွက် Scapy library လိုအပ်ပါသည်
# Install လုပ်ရန်: pip install scapy
try:
    from scapy.all import *
except ImportError:
    print("Error: Scapy module not found.")
    print("Please run: pip install scapy")
    sys.exit(1)

# =================CONFIGURATIONS=================
TARGET_PORTS = [9000, 9146]
OUTPUT_FOLDER = "decoded_game_data"
# ================================================

# Folder မရှိသေးလျှင် အသစ်ဆောက်မည်
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)

def ai_method_decoder(raw_bytes):
    """
    ကျွန်ုပ် (AI) ရှင်းပြခဲ့သော နည်းလမ်း ၃ ခုဖြင့် Data ကို ဘာသာပြန်ခြင်း
    """
    analysis_result = {
        "hex_preview": "",
        "decoded_text": "",
        "json_data": [],
        "pattern_found": []
    }

    # ၁။ ASCII/Unicode Conversion (စာသားပြောင်းလဲခြင်း)
    # Hex to String ကြိုးစားမည် (Chinese character များပါ ဖတ်နိုင်အောင် utf-8 သုံးသည်)
    try:
        text_content = raw_bytes.decode('utf-8', errors='ignore')
        # လူဖတ်၍ရသော စာလုံးများကိုသာ ချန်ထားမည်
        clean_text = "".join([c if c.isprintable() else '.' for c in text_content])
        analysis_result["decoded_text"] = clean_text
    except:
        analysis_result["decoded_text"] = "[Decode Error]"

    # Hex အဖြစ်ပြောင်းလဲခြင်း (ပထမ ၃၀ လုံးခန့်သာပြမည်)
    hex_str = raw_bytes.hex()
    analysis_result["hex_preview"] = hex_str[:60] + "..." if len(hex_str) > 60 else hex_str

    # JSON Extraction (JSON format များကို ရှာဖွေခြင်း)
    # Regex သုံးပြီး {...} ပုံစံများကို ရှာဖွေပါမည်
    potential_jsons = re.findall(r'\{.*?\}', text_content)
    for p_json in potential_jsons:
        try:
            # JSON ဟုတ်မဟုတ် စစ်ဆေးခြင်း
            parsed_json = json.loads(p_json)
            analysis_result["json_data"].append(parsed_json)
        except:
            continue

    # ၂။ Pattern Recognition (Headers ရှာဖွေခြင်း)
    # ဥပမာ - 1b aa, 50 ac, c1 aa
    if hex_str.startswith("1baa"):
        analysis_result["pattern_found"].append("Type: Login/Init (1b aa)")
    elif hex_str.startswith("50ac"):
        analysis_result["pattern_found"].append("Type: Game State Update (50 ac)")
    elif hex_str.startswith("c1aa"):
        analysis_result["pattern_found"].append("Type: Heartbeat/Command (c1 aa)")
    
    return analysis_result

def process_pcap_file(file_path):
    print(f"[*] Processing file: {file_path}...")
    packets = rdpcap(file_path)
    
    output_filename = os.path.join(OUTPUT_FOLDER, f"result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    with open(output_filename, "w", encoding="utf-8") as f:
        count = 0
        for packet in packets:
            # TCP နှင့် Raw Data ပါမှ ဆက်လုပ်မည်
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Port 9000 သို့မဟုတ် 9146 နှင့် သက်ဆိုင်မှ ဖတ်မည်
                if src_port in TARGET_PORTS or dst_port in TARGET_PORTS:
                    payload = packet[Raw].load
                    
                    # AI Decoder ကို ခေါ်ယူအသုံးပြုခြင်း
                    result = ai_method_decoder(payload)
                    
                    # Result ရေးသားခြင်း
                    f.write(f"Packet #{count} | {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}\n")
                    f.write(f"Hex: {result['hex_preview']}\n")
                    
                    if result['pattern_found']:
                        f.write(f"Pattern: {', '.join(result['pattern_found'])}\n")
                    
                    f.write(f"Text: {result['decoded_text']}\n")
                    
                    if result['json_data']:
                        f.write("JSON DETECTED:\n")
                        f.write(json.dumps(result['json_data'], indent=2, ensure_ascii=False))
                        f.write("\n")
                    
                    f.write("-" * 60 + "\n")
                    count += 1
        
    print(f"[SUCCESS] {count} packets analyzed.")
    print(f"Results saved to: {output_filename}")

if __name__ == "__main__":
    # ဖိုင်အမည်ကို ဒီမှာ ပြင်ပါ (သို့မဟုတ် upload တင်ထားသော pcap file အမည်ထည့်ပါ)
    pcap_file = "game_capture.pcap" 
    
    if os.path.exists(pcap_file):
        process_pcap_file(pcap_file)
    else:
        print(f"File '{pcap_file}' not found. Please upload your PCAPdroid file first.")

