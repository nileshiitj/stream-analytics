import os
import subprocess
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import traceback

class TrafficAnalyzer:
    def __init__(self):
        """
        Initialize TrafficAnalyzer with default configuration and setup.
        """
        self.config = {
            'threshold': 1000,  # Anomaly threshold for packet count
            'start_date': '2004/10/04:20',
            'end_date': '2005/01/08:05',
            'bin_interval': 60  # Interval in seconds
        }

        self.output_dir = "output"
        os.makedirs(self.output_dir, exist_ok=True)

        # Load configuration settings
        self.threshold = self.config['threshold']
        self.start_date = self.config['start_date']
        self.end_date = self.config['end_date']
        self.bin_interval = self.config['bin_interval']

        self._verify_environment()

    def _verify_environment(self):
        """
        Check for necessary SiLK environment variables and files.
        """
        print("\n[INFO] Validating SiLK environment setup...")
        silk_dir = os.getenv('SILK_DATA_ROOTDIR')
        silk_config = os.getenv('SILK_CONFIG_FILE')

        print(f"  - SILK_DATA_ROOTDIR: {silk_dir or 'Not Set'}")
        print(f"  - SILK_CONFIG_FILE: {silk_config or 'Not Set'}")

        if not silk_dir or not silk_config:
            print("[WARNING] Missing required SiLK environment variables.")
        if silk_dir and not os.path.exists(silk_dir):
            print(f"[WARNING] The directory '{silk_dir}' does not exist.")
        if silk_config and not os.path.exists(silk_config):
            print(f"[WARNING] The file '{silk_config}' does not exist.")

    def validate_silk_tools(self):
        """
        Confirm that SiLK tools are installed and operational.
        """
        print("\n[INFO] Verifying SiLK tools...")
        try:
            cmd = ['rwfilter', '--version']
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(f"[SUCCESS] SiLK Tools Verified: {result.stdout.strip()}")
            return True
        except Exception as e:
            print(f"[ERROR] Unable to verify SiLK tools: {e}")
            return False

    def fetch_data(self):
        """
        Retrieve TCP traffic data using SiLK rwfilter and rwstats commands.
        """
        print("\n[INFO] Fetching traffic data...")
        rwfilter_cmd = [
            'rwfilter',
            f'--start-date={self.start_date}',
            f'--end-date={self.end_date}',
            '--sensor=S0',
            '--proto=6',  # TCP protocol
            '--type=all',
            '--pass=stdout'
        ]

        rwstats_cmd = [
            'rwstats',
            '--fields=stime',
            '--values=packets,bytes',
            '--bin-size=60',
            '--delimited=|',
            '--count=0'
        ]

        try:
            # Combine commands with piping
            cmd = ' | '.join([' '.join(rwfilter_cmd), ' '.join(rwstats_cmd)])
            print(f"  - Executing command: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.stderr:
                print(f"[ERROR] Command execution error: {result.stderr}")

            if result.stdout:
                print("[INFO] Successfully fetched data. Previewing first 500 characters:")
                print(result.stdout[:500])
                return self._parse_output(result.stdout)
            else:
                print("[ERROR] No data retrieved. Check the command or data source.")
                return None
        except Exception as e:
            print(f"[ERROR] Failed to fetch data: {e}")
            traceback.print_exc()
            return None

    def _parse_output(self, output):
        """
        Convert raw rwstats output to a pandas DataFrame.
        """
        print("\n[INFO] Parsing traffic data...")
        records = []

        for line in output.splitlines():
            if line and not line.startswith('#'):
                parts = line.split('|')
                if len(parts) >= 3:
                    try:
                        record = {
                            'timestamp': pd.to_datetime(parts[0].strip()),
                            'packets': int(float(parts[1].strip())),
                            'bytes': int(float(parts[2].strip()))
                        }
                        records.append(record)
                    except ValueError as ve:
                        print(f"[WARNING] Skipping line due to parsing error: {line} ({ve})")

        if not records:
            print("[ERROR] No records parsed from the data.")
            return None

        df = pd.DataFrame(records).sort_values(by='timestamp')
        print("[SUCCESS] Data parsed successfully. Sample:")
        print(df.head())
        return df

    def analyze_data(self, df):
        """
        Classify traffic and detect anomalies based on packet counts.
        """
        print("\n[INFO] Analyzing traffic data...")

        # Traffic classification
        df['traffic_category'] = pd.cut(
            df['packets'],
            bins=[0, 600, 6000, 60000, float('inf')],
            labels=['Low', 'Moderate', 'High', 'Very High']
        )

        # Detect anomalies
        anomalies = df[df['packets'] > self.threshold]
        print(f"[INFO] Anomalies Detected: {len(anomalies)}")
        return df, anomalies

    def visualize_data(self, df, anomalies):
        """
        Generate visual representations of traffic data.
        """
        print("\n[INFO] Generating visualizations...")

        plt.figure(figsize=(15, 10))

        # Plot traffic data
        plt.plot(df['timestamp'], df['packets'], label='Traffic Volume')
        if not anomalies.empty:
            plt.scatter(anomalies['timestamp'], anomalies['packets'], color='red', label='Anomalies')

        plt.title('Traffic Analysis')
        plt.xlabel('Time')
        plt.ylabel('Packets')
        plt.legend()
        plt.tight_layout()

        output_path = os.path.join(self.output_dir, 'traffic_visualization.png')
        plt.savefig(output_path)
        plt.close()
        print(f"[SUCCESS] Visualization saved to {output_path}")

    def save_results(self, df, anomalies):
        """
        Save the analyzed results to a file.
        """
        print("\n[INFO] Saving analysis results...")
        output_path = os.path.join(self.output_dir, 'analysis_results.txt')
        with open(output_path, 'w') as file:
            file.write("Traffic Analysis Results\n")
            file.write("=========================\n")
            file.write("\nSummary:\n")
            file.write(df.describe().to_string())
            file.write("\n\nAnomalies:\n")
            if not anomalies.empty:
                file.write(anomalies.to_string())
            else:
                file.write("No anomalies detected.")

        print(f"[SUCCESS] Results saved to {output_path}")

    def run_analysis(self):
        """
        Main function to run the complete analysis.
        """
        print("\n=== Starting Traffic Analysis ===")
        if not self.validate_silk_tools():
            print("[ERROR] SiLK tools not configured properly. Exiting.")
            return

        df = self.fetch_data()
        if df is None:
            print("[ERROR] Failed to fetch traffic data. Exiting.")
            return

        df, anomalies = self.analyze_data(df)
        self.visualize_data(df, anomalies)
        self.save_results(df, anomalies)
        print("\n=== Traffic Analysis Complete ===")

if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    analyzer.run_analysis()
