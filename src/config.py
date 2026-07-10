'''
config.py - central configuration for the entire project
- all constants, paths and settings live here
- every other file imports from this file
'''

#-----import-----
from pathlib import Path

#-----paths-----

#Path(__file__) is the file's location
#.parent.parent is to go up 2 levels to the project root
BASE_DIR = Path(__file__).parent.parent

#subfolders built from the root that works on any operating system
DATA_DIR = BASE_DIR / "data"        #where datasets live
MODELS_DIR = BASE_DIR / "models"    #where trained models are saved
LOGS_DIR = BASE_DIR / "logs"        #where log files are written

#dataset files
TRAIN_PATH = DATA_DIR / "KDDTrain+.txt"
TEST_PATH = DATA_DIR / "KDDTest+.txt"

#trained model and scaler saved after training
#joblib loads these at dashboard startup instead of retraining
MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"

#SQLite Database used to store every flagged anomaly
DB_PATH = BASE_DIR / "anomalies.db"
#log file to record every event, warning and error with timestamps
LOG_PATH = LOGS_DIR / "anomaly.log"

#-----model settings-----
CONTAMINATION = 0.1 #expected proportion of anomalies in the data
RANDOM_STATE = 42   #makes results reproducible
TEST_SIZE = 0.2     #proportion of data held back for testing the model

#-----thresholds-----
#these convert the model's raw 0-1 score into a threat level
CRITICAL_THRESHOLD = 0.70
MEDIUM_THRESHOLD = 0.55
LOW_THRESHOLD = 0.40

#-----port risk levels-----
#high risk = critical services that attackers frequently target
HIGH_RISK_PORTS = {22, 23, 3306, 5432, 1433, 445, 139, 3389}
#medium risk = usually run web servers or API
#less dangerous than database or remote-access ports but still risky
MEDIUM_RISK_PORTS = {80, 8080, 8443, 8000}

#-----NSL-KDD column names-----
#the dataset has no headers, so we define all 43 column names here
COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty"
]

#-----categorical and feature columns-----
#these 3 columns contained text which need encoding before the ML model can use them
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

#feature columns are everything except label and difficulty
#they will be encoded separately
FEATURE_COLS = [c for c in COLUMNS if c not in ["label", "difficulty"] + CATEGORICAL_COLS]
