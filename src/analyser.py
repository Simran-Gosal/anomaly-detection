'''
analyser.py
- uses threat scores from the model and categorises attacks
- takes port number and reads human readable description
- takes a threat level and port number and recommends an action
- assembles everything into a dictionary - this will be saved to the db
  and displayed on the dashboard
- flags warnings if it is an anomaly
'''

#-----imports-----
import numpy as np
from datetime import datetime, timezone
from src.config import CRITICAL_THRESHOLD, MEDIUM_THRESHOLD, LOW_THRESHOLD, HIGH_RISK_PORTS, MEDIUM_RISK_PORTS
from src.logger import get_logger

#setup logger
logger = get_logger(__name__)

#create dictionary that maps port numbers to descriptions
ATTACK_PORT_LABELS ={
    22: "SSH - brute force risk",
    23: "Telnet - unencrypted, high risk",
    3306: "MySQL - database exposure",
    5432: "PostgreSQL - database exposure",
    1433: "MSSQL - database exposure",
    445: "SMB: ransomware vector",
    139: "NetBIOS - lateral movement risk",
    3389: "RDP - remote access exploitation",
}

#-----function to calculate threat level-----
def calculate_threat_level(score: float) -> str:
    #return appropriate comments for threat levels
    if score >= CRITICAL_THRESHOLD:
        return "Critical"
    elif score >= MEDIUM_THRESHOLD:
        return "Medium"
    elif score >= LOW_THRESHOLD:
        return "Low"
    else:
        return "Clean"

#-----function to get port context in human readable format-----
def get_port_context(port: int) -> str:
    #check if port is in dictionary and output description
    if port in ATTACK_PORT_LABELS:
        return f"Port {port}: {ATTACK_PORT_LABELS[port]}"
    else:
        #if port not in dict, output port number for exploration
        return f"Port {port}"

#-----function to recommend action based on threat level and port risk-----
def recommend_action(threat_level : str, port: int) -> str:
    #appropriate action based on threat level and port risk
    if threat_level == "Critical":
        return "BLOCK IMMEDIATELY"
    elif threat_level == "Medium" and port in HIGH_RISK_PORTS:
        return "BLOCK - high-risk port"
    elif threat_level == "Medium":
        return "MONITOR - investigate"
    elif threat_level == "Low":
        return "LOG - Watch for pattern"
    elif threat_level == "Clean":
        return "ALLOW"

#-----master function to analyse packet and create result dictionary-----
def analyse_packet(row: np.ndarray, model, scaler, ip : str, port: int) -> dict:
    #import here to avoid circular imports between model.py and analyser.py
    from src.model import predict_single

    #get anomaly prediction and threat score from isolation forest
    is_anomaly, score = predict_single (row, model, scaler)

    #convert raw score to human readable threat level
    threat_level = calculate_threat_level(score)

    #recommend action
    action = recommend_action(threat_level, port)

    #get human readable port description
    description = get_port_context(port)

    #log warning if anomaly detected - appears in anomaly.log
    if is_anomaly:
        logger.warning(f"ANOMALY | {ip}:{port} | {threat_level} | Score: {score:.3f} | {action}")
        
    #assemble result dictionary - this gets saved SQLite and displayed on dashboard
    result ={
        "timestamp":    datetime.now(timezone.utc).isoformat(),  #UTC time of detection
        "ip":           ip,                             #source IP address
        "port":         port,                           #destination port   
        "port_context": description,                    #human readable port label
        "is_anomaly":   is_anomaly,                     #TRUE or FALSE
        "score":        round(score, 4),                #threat score to 4 d.p
        "threat_level": threat_level,                   #Critical/Medium/Low/Clean
        "action":       action                          #recommended response
        }
    return result

if __name__ == "__main__":
    #-----imports-----
    from src.model import load_model
    from src.data_loader import load_dataset, prepare_data
    from src.config import TEST_PATH

    #load model using load_model
    model, scaler = load_model()

    #load and prepare the test dataset
    df_test = load_dataset(TEST_PATH)
    X_test, y_test, feature_cols, encoders = prepare_data(df_test)

    #loop through the first 5 rows of X_test
    for i, row in enumerate(X_test[:5]):
        #call analyse_packet with a fake IP and port
        result = analyse_packet(row, model, scaler, "192.168.1.1", 22)
        #print each result
        print(f"\nPacket {i+1}:")
        for key, value in result.items():
            print(f"{key}: {value}")
    
