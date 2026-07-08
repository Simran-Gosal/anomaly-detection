'''
logger.py is the central logging configuration for the entire project
- sets up logging to both a file and terminal simultaneously
- every other file calls get_logger(__name__) to get its own names logger
'''

import logging
from src.config import LOG_PATH

#-----create logs directory of it does not exist-----
'''
this runs automatically when an file imports logger.py
ensures the logs folder exists before trying to write to it
'''
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

'''
logging.basicConfig() is a function defined inside Python's built in logging module
- using a function call to configure the logging system for the entire project
'''
logging.basicConfig(
    #tells logger what minimal severity to record
    #records INFO, WARNING, ERROR AND CRITICAL
    level = logging.INFO,
    #timestamp, levelname, which file logged it and the message is recorded
    format ="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    #list of handlers
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)

'''
A handler controls where the log output goes
here, it goes to two places simultaneously
- FileHandler = writes log lines to anomaly.log file on disk. permanent record
- StreamHandler = prints log lines to the terminal, so you can see them live while program runs
'''

#type hint shows function return a logging.Logger object 
def get_logger(name: str) -> logging.Logger:
    #returns a names logger (used in format above) - in every log line this logger writes
    #called with get_logger(__name__) where __name__ is automatically the current file name
    return logging.getLogger(name)
