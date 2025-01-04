# TCP Traffic Analysis Project
## Stream Analytics Course Assignment

### Project Description
This project analyzes TCP traffic data from the LBNL/ICSI Enterprise Trace dataset using the SiLK suite. The analysis includes:
- TCP traffic flow analysis
- Traffic classification using VFDT and On-Demand Classification
- Anomaly detection for high-volume traffic
- Visualization of traffic patterns and classifications

### Prerequisites
- Ubuntu OS (>= 18.04)
- Python 3.8 or higher
- SiLK suite
- Required Python packages (listed in requirements.txt)

### Installation Steps

1. Install SiLK suite:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev libfixbuf-dev flex bison cmake
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Configure SiLK:
```bash
# Set environment variables
export SILK_DATA_ROOTDIR=/path/to/SiLK-LBNL-05
export SILK_CONFIG_FILE=/etc/silk/silk.conf

# Create config directory
sudo mkdir -p /etc/silk
sudo cp SiLK-LBNL-05/silk.conf /etc/silk/
```

### Project Structure
```
stream_analytics/
├── src/
│   ├── tcp_analyzers.py      # Main analysis script
│   └── classifiers/          # Classification algorithms
├── config.csv               # Configuration parameters
├── requirements.txt         # Python dependencies
├── README.md               # Project documentation
└── outputfile.txt          # Analysis results
```

### Configuration
The config.csv file contains the following parameters:
- anomaly_threshold: Threshold for anomaly detection (packets/sec)
- start_date: Analysis start date
- end_date: Analysis end date
- bin_size: Time bin size for analysis (seconds)

### Running the Analysis
1. Ensure environment variables are set:
```bash
export SILK_DATA_ROOTDIR=/path/to/SiLK-LBNL-05
export SILK_CONFIG_FILE=/etc/silk/silk.conf
```

2. Run the analyzer:
```bash
python src/tcp_analyzers.py
```

3. View results:
- Check outputfile.txt for detailed analysis
- View visualizations in output/lbnl_analysis.png

### Output Files
1. outputfile.txt: Contains
   - Overall traffic statistics
   - Classification results
   - Anomaly detection results
   - Summary metrics

2. Visualizations (output/lbnl_analysis.png):
   - TCP traffic over time
   - Traffic classification distribution
   - Anomaly detection results

### Authors
- Student 1 [Roll Number]
- Student 2 [Roll Number]

### Note
This code is submitted as part of the Stream Analytics course assignment. No modifications to the code are allowed after submission. Only configuration file changes are permitted.
