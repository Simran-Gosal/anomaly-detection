'''
data_loader.py - load, explore, encode and return dataset
'''
#-----imports-----
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from src.config import TRAIN_PATH, TEST_PATH, COLUMNS, CATEGORICAL_COLS
from src.logger import get_logger

#setup logger
logger = get_logger(__name__)

#-----function to load dataset-----
def load_dataset(path) -> pd.DataFrame:
    #log a message saying what file is loading
    logger.info(f"Loading dataset from {path}")
    #use pd_read_csv
    df = pd.read_csv(path, header=None, names=COLUMNS)
    #log how records were loaded
    logger.info(f"Loaded {len(df):,} records")
    #return the DataFrame
    return df

#-----function to explore dataset-----
#clear header to make is readable
def explore_dataset(df):
    print("\n" + "-"*50)
    print("DATASET EXPLORATION")
    print("-"*50)
    
    #print shape of dataset
    print(df.shape)
    
    #print total missing values
    print("\n" + "-"*50)
    print("MISSING VALUES PER COLUMN")
    print("-"*50)
    print(f"{df.isnull().sum()}") #per column
    print(f"TOTAL MISSING VALUES: {df.isnull().sum().sum()}") #total missing values
    
    #Label Distribution - how many records are normal vs each attack type
    print(f"\nLabel Distribution:")
    print("-"*50 + "\n")
    print(df["label"].value_counts())

#-----function to encode features-----
def encode_features(df: pd.DataFrame, encoders : dict | None = None, fit: bool = True):
    #never modify original DataFrame directly
    df = df.copy()
    #if no encoder dictionary was passed in, create an empty one
    if encoders is None:
        encoders = {}
    for cols in CATEGORICAL_COLS:
        if fit:
            le = LabelEncoder()
            df[cols] = le.fit_transform(df[cols])
            encoders[cols] = le
        else:
            le = encoders[cols]
            df[cols]=le.transform(df[cols]) #transform only
    logger.info(f"Encoded: {len(CATEGORICAL_COLS)} CATEGORICAL COLUMNS")
    return df, encoders

#-----function to prepare data-----
def prepare_data(df: pd.DataFrame, encoders : dict | None = None, fit: bool = True):
    #call encode_features to encode the categorical columns
    df, encoders = encode_features(df, encoders, fit)
    #select numerical columns
    feature_cols = [c for c in df.columns if c not in ["label", "difficulty"]]
    #convert to NumPy array
    X = df[feature_cols].values
    #separate labels to their own variable
    y = df["label"]
    #log shape of feature matrix
    logger.info(f"Feature Matrix Shape: {X.shape}")
    #return x, y, feature_cols and encoders
    return X, y, feature_cols, encoders

#-----main------
if __name__ == "__main__":
    #load training data
    df_train = load_dataset(TRAIN_PATH)

    #explore training data
    explore_dataset(df_train)

    #prepare training data
    X, y, feature_cols, encoders = prepare_data(df_train)

    #print the shape of X
    print(X.shape)

    #print how many normal vs attack records exist
    #count normal records
    normal_count = (y == "normal").sum()

    #count attack records
    attack_count = (y != "normal").sum()

    #print record counts
    print(f"Normal records: {normal_count:,}")
    print(f"Attack records: {attack_count:,}")

    

