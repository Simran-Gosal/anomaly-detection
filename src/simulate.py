'''
simulate.py
- runs the full test dataset through the pipeline
- inserts all anomalies into the database
- populates the dashboard with real data
'''

#-----imports-----
import random
from datetime import datetime
from src.model import load_model
from src.data_loader import load_dataset, prepare_data
from src.analyser import analyse_packet
from src.database import insert_batch, initialise_database
from src.config import TEST_PATH
from src.logger import get_logger

#-----logger setup-----
logger = get_logger(__name__)

def run_simulation():
    #initialise db
    initialise_database()

    #load model
    model, scaler = load_model()
    
    #load and prepare test dataset
    df_test = load_dataset(TEST_PATH)
    X_test, y_test, feature_cols, encoders = prepare_data(df_test)
    
    #generate 1000 random IPS using random.seed(42)
    random.seed(42)
    fake_ips = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,124)}" for i in range (1000)]

    #define a fake ports list
    fake_ports = [22,23,3306,5432,1433,445,139,3389,80,8080,8443,8000,443,
                  53,25,110,143,21,990,993,995,8888,9000,4000,5000,6379,27017]
    
    #create empty batch list
    batch = []
    #loop through every row in X_test
    for i, row in enumerate(X_test):
        #fake ip and port for each row
        ip = fake_ips[i % len(fake_ips)]
        port = fake_ports[i % len(fake_ports)]
        result = analyse_packet(row, model, scaler, ip, port)
        batch.append(result)

        #every 100 rows - call insert_batch, clear batch and log progress
        if len(batch) >= 100:
            insert_batch(batch)
            batch.clear()
            logger.info(f"Processed {i+1} rows...")

    #after loop, insert any remaining records in batch
    if batch:
        insert_batch(batch)

    #print total anomalies inserted
    logger.info(f"Simulation complete - processed {len(X_test)} rows")


if __name__ == "__main__":
    run_simulation()
