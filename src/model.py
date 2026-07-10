'''
model.py - for model training and evaluation
- TRAIN - fit isolation forest on normal records only
- EVALUATE - test is against test dataset and print metrics
- SAVE - save trained model and scaler to disk using joblib
- LOAD - load saved model and scaler when dashboard starts
- PREDICT - score a single conncection and return a 0-1 threat score
'''

#-----imports-----
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from src.config import MODEL_PATH, SCALER_PATH, CONTAMINATION, RANDOM_STATE, MODELS_DIR, TEST_PATH, TRAIN_PATH
from src.logger import get_logger

#-----setup logger-----
logger = get_logger(__name__)

#------function to train model-----
def train_model(X_train: np.ndarray, y_train: pd.Series):
    '''
    train_model
    - scales training data and filters normal records
    - creates and trains isolation forest
    - saves model and scaler and returns both
    '''
    #step 1 - scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train) #fit_transform on training data
    #fit_tranform learns mean and standard deviation of each feature from training data + scales everything
    
    #step 2 - filter to normal records only
    #create boolean makes - True where label is normal
    normal_mask = y_train == "normal"
    #apply mask to get only normal rows
    X_normal = X_scaled[normal_mask]
    logger.info(f"Training on {X_normal.shape[0]:,} normal records")
    
    #step 3 - create and train isolation forest
    model = IsolationForest(
        contamination = CONTAMINATION, #from config
        random_state = RANDOM_STATE,   #from config
        n_estimators = 200,            #number of trees
        n_jobs = -1                    #tell scikit-learn to use all CPU CORES = TRAIN FASTER
    )
    #fit on normal records only
    model.fit(X_normal)

    #log that training is complete
    logger.info("Isolation Forest Training is complete")
    
    #step 4 - save model and scaler
    #make sure folder exists
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    #save model and scaler to disk
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    
    #log where they were saved
    logger.info(f"model saved here: {MODEL_PATH}")
    logger.info(f"scaler saved here: {SCALER_PATH}")
    
    #step 5 - return model and scaler
    return model, scaler

#-----function to evaluate model-----
def evaluate_model(model, scaler, X_test:np.ndarray, y_test: pd.Series):
    '''
    evaluate_model
    - takes trained model and test data
    - runs predictions and prints how well the model performed
    '''
    #step 1 - scale test data
    X_scaled = scaler.transform(X_test)
    
    #step 2 - get predictions
    raw_preds = model.predict(X_scaled) #returns -1 (anomaly) or 1 (normal)
    
    #step 3 - convert to binary
    y_pred_binary = (raw_preds == -1).astype(int)     #-1 becomes 1 (anomaly), 1 becomes 0 (normal)
    y_true_binary = (y_test != "normal").astype(int)  #anything not normal is y_test becomes 1 (attack)
    
    #step 4 - print confusion matrix and classification report
    cm = confusion_matrix(y_true_binary, y_pred_binary)
    report = classification_report(y_true_binary, y_pred_binary, target_names=["Normal", "Attack"])

    #print results
    print("\n" + "-"*50)
    print("MODEL EVALUATION")
    print("-"*50)
    print("\nCONFUSION MATRIX:")
    print(cm)
    print("\nCLASSIFICATION REPORT:")
    print(report)
    print("-"*50 + "\n")
    
    #step 5 - return results
    return {"predictions": y_pred_binary, "confusion": cm}


#-----function to load model-----
def load_model():
    '''
    load_model
    - will load the model and scaler from disk
    - log this and return both
    '''
    #check if model file exists
    if not MODEL_PATH.exists():
        #file does not exist, raise an error
        raise FileNotFoundError(f"No trained model found at {MODEL_PATH}. Run train_model() first.")

    #load model from disk
    model = joblib.load(MODEL_PATH)

    #load scaler from disk
    scaler = joblib.load(SCALER_PATH)

    #log success
    logger.info("BOTH scaler and model loaded successfully")

    #return both
    return model, scaler


#-----function to predict on a single row-----
def predict_single(row: np.ndarray, model, scaler) -> tuple[bool,float]:
    '''
    predict_single

    When the dashboard is running live, network connections come in one
    at a time. For each connection, it needs to:
    - take a single row of 41 features
    - scale is using the same scaler from training
    - pass it through the model to get a prediction
    - convert the raw score to a 0-1 threat score
    - and return whether it is an anomaly and its threat score
    '''
    #reshape and scale and assign it to row_scaled
    row_scaled = scaler.transform(row.reshape(1, -1))   # covert shape (41,) to shape  (1,41)

    #pass it through the model for prediction
    prediction = model.predict(row_scaled)[0]
    is_anomaly = prediction == -1 #True if anomaly, False if normal

    #convert raw score to a 0-1 threat score 
    raw_score = model.decision_function(row_scaled)[0]
    threat_score = float(np.clip(0.5 - raw_score, 0, 1))

    #log an anomaly when detected
    if is_anomaly:
        logger.warning(f"Anomaly detection - threat score: {threat_score:.3f}")

    #return whether it is an anomaly and its threat score
    return is_anomaly, threat_score
    

#-----main-----
if __name__ == "__main__":
    #step 1 - imports
    from src.data_loader import load_dataset, prepare_data

    #step 2 - load training data
    df_train = load_dataset(TRAIN_PATH)

    #step 3 - load test data
    df_test = load_dataset(TEST_PATH)
    
    #step 4 - prepare training data
    X_train, y_train, feature_cols, encoders = prepare_data(df_train)

    #step 5 - prepare test data with fit=false, using the same encoders
    X_test, y_test, feature_cols, encoders = prepare_data(df_test, encoders, False)

    #step 6 - call train_model with training data
    model, scaler = train_model(X_train, y_train)

    #step 7 - call evaluate_model with test data
    evaluate_model(model, scaler, X_test, y_test)
    
    #step 8 - test predict_single on the first row or X_test and print result
    #get one row from the dataset
    row = X_test[0]

    #pass it to predict_single
    is_anomaly, score =  predict_single(row, model, scaler)

    print(f" anomaly: {is_anomaly}, and score: {score}")
    



