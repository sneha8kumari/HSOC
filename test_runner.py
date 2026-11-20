import os, sys
os.environ["YOLO_CONFIG_DIR"] = "./data"
os.environ["ULTRALYTICS_CONFIG_DIR"] = "./data"
sys.path.insert(0, os.path.abspath("."))

from tests.unit.test_streaming_ingest import test_syslog_ingest_event_creation
test_syslog_ingest_event_creation()
print("test_syslog_ingest_event_creation passed!")
