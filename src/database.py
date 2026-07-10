'''
database.py
- create database and table
- save a single result dictionary to the database
- save a batch of results at once
- query recent anomalies - get the latest flagged packets for the dashboard to display
- query threat summary - count how many critical medium, low anomalies exists
'''

#-----imports-----
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from src.config import DB_PATH
from src.logger import get_logger

#setup logger
logger = get_logger(__name__)

#-----SQL to create anomalies table-----
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS anomalies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    ip           TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    port_context TEXT,
    is_anomaly   INTEGER,
    score        REAL    NOT NULL,
    threat_level TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    created_at   TEXT    DEFAULT (datetime('now'))
);
"""

#-----context manager for database connections-----
@contextmanager
def get_connection():
    #open connection to DB_PATH
    conn = sqlite3.connect(DB_PATH)
    #set row_factory so results come back as dictionaries
    conn.row_factory = sqlite3.Row
    #yield the connection - code inside 'with' runs here
    try:
        #commit if no error
        yield conn
        conn.commit()
    except Exception as e:
        #rollback if error occurs
        conn.rollback()
        logger.error(f"Database error: {e}")
        #re-raise the error so calling code knows
        raise
    finally:
        #always close the connection - whether success or failure
        conn.close()
    
#-----function to initialise database-----
def initialise_database() -> None:
    '''create anomalies table if it does not already exist'''
    #use function as context manager with 'with' - else the connection never opens properly
    #and conn will not be defined
    with get_connection() as conn:
        conn.execute(CREATE_TABLE_SQL)
    logger.info(f"Database initialised at {DB_PATH}")
    
#-----function to insert a single anomaly-----
def insert_anomaly(result : dict) -> int:
    '''insert a single anomaly result into the database - return new row id'''
    #sql can't sit loose in middle of python code - needs to be stored as python string variable
    sql = """
    INSERT INTO anomalies 
        (timestamp, ip, port, port_context, is_anomaly, score, threat_level, action)
    VALUES 
        (:timestamp, :ip, :port, :port_context, :is_anomaly, :score, :threat_level, :action)
    """
    with get_connection() as conn:
        cursor = conn.execute(sql, result)
        return cursor.lastrowid

#-----function to insert a batch of anomalies-----
def insert_batch(list_of_dicts : list) -> int:
    '''insert a batch of anomaly results into the database - filter to anomalies only'''
    sql = """
    INSERT INTO anomalies 
        (timestamp, ip, port, port_context, is_anomaly, score, threat_level, action)
    VALUES 
        (:timestamp, :ip, :port, :port_context, :is_anomaly, :score, :threat_level, :action)
    """
    #filter to only flagged anomalies
    anomalies = [l for l in list_of_dicts if l["is_anomaly"]]
    with get_connection() as conn:
        #use executemany to insert all at once
        cursor = conn.executemany(sql, anomalies)
        #log how many were inserted
        logger.info(f"Inserted {len(anomalies)} anomalies into database")
        #return count of inserted records
        return len(anomalies)

#-----function to get recent anomalies-----
def get_recent_anomalies(limit : int = 100) -> list:
    '''query database and return most recent flagged anomalies for dashboard to display'''
    #query anomalies table ordered by timestamp descending
    sql = """
    SELECT * FROM anomalies 
    ORDER BY timestamp DESC 
    LIMIT ?
    """
    with get_connection() as conn:
        cursor = conn.execute(sql,(limit,))
        #return results as a list of dictionaries
        return[dict(row) for row in cursor.fetchall()]

#-----function to get threat summary-----
def get_threat_summary() -> list:
    '''queries db and count how many anomlies exist per threat level'''
    #dashboard uses this to populate the metric cards
    sql = """
    SELECT threat_level, COUNT(*) as count, ROUND(AVG(score), 3) as avg_score
    FROM anomalies
    GROUP BY threat_level
    ORDER BY avg_score DESC
    """
    with get_connection() as conn:
        cursor = conn.execute(sql)
        return[dict(row) for row in cursor.fetchall()]

if __name__ == "__main__":
    #initialise database
    initialise_database()

    #-----imports-----
    from src.model import load_model
    from src.data_loader import load_dataset, prepare_data
    from src.analyser import analyse_packet
    from src.config import TEST_PATH

    #load model
    model, scaler = load_model()

    #load test data
    df_test = load_dataset(TEST_PATH)
    X_test, y_test, feature_cols, encoders = prepare_data(df_test)
    
    results=[]
    #loop through first 20 rows of X_test and run analyse_packet
    for i, row in enumerate(X_test[:20]):
        result = analyse_packet(row, model, scaler, "10.0.0.1", 23)
        results.append(result)
        
    #insert batch
    insert_batch(results)

    #get 10 recent anomalies
    recent = get_recent_anomalies(10)
    print(f"\nRecent anomalies: {len(recent)}")
    for r in recent:
        print(f"  {r['ip']} | {r['threat_level']} | {r['score']}")

    #get threat summary    
    summary = get_threat_summary()
    print(f"\nThreat summary:")
    for s in summary:
        print(f"  {s['threat_level']}: {s['count']} records")
        
