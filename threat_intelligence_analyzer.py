import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Any
import logging
import requests
from datetime import datetime

class ThreatIntelligenceAnalyzer:
    def __init__(self, log_file='security_analysis.log'):
        """
        Initialize the Threat Intelligence Analyzer
        
        Args:
            log_file (str): Path to the log file for tracking security events
        """
        # Configure logging
        logging.basicConfig(
            filename=log_file, 
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Machine learning anomaly detection model
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Assume 10% potential threats
            random_state=42
        )
        
        # MITRE ATT&CK framework mapping
        self.mitre_tactics = {
            'initial_access': ['drive-by-compromise', 'phishing'],
            'execution': ['command-and-scripting', 'user-execution'],
            'persistence': ['account-manipulation', 'boot-or-logon-initialization'],
            'privilege_escalation': ['exploitation-for-privilege-escalation'],
            'defense_evasion': ['obfuscated-files', 'indicator-removal']
        }
    
    def parse_security_logs(self, log_data: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Parse security logs and convert to structured DataFrame
        
        Args:
            log_data (List[Dict]): Raw security log entries
        
        Returns:
            pd.DataFrame: Processed security log data
        """
        try:
            df = pd.DataFrame(log_data)
            
            # Basic log enrichment
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['is_anomalous'] = False
            
            self.logger.info(f"Parsed {len(df)} log entries successfully")
            return df
        except Exception as e:
            self.logger.error(f"Log parsing error: {e}")
            raise
    
    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply machine learning anomaly detection
        
        Args:
            df (pd.DataFrame): Security log DataFrame
        
        Returns:
            pd.DataFrame: DataFrame with anomaly detection results
        """
        # Select numerical features for anomaly detection
        numerical_features = ['source_port', 'destination_port', 'packet_size']
        
        # Fit and predict anomalies
        try:
            anomaly_scores = self.anomaly_detector.fit_predict(df[numerical_features])
            df['is_anomalous'] = anomaly_scores == -1
            
            anomaly_count = df['is_anomalous'].sum()
            self.logger.info(f"Detected {anomaly_count} potential security anomalies")
            
            return df
        except Exception as e:
            self.logger.error(f"Anomaly detection error: {e}")
            return df
    
    def map_mitre_tactics(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Map log entries to MITRE ATT&CK tactics
        
        Args:
            df (pd.DataFrame): Security log DataFrame
        
        Returns:
            pd.DataFrame: DataFrame with MITRE tactic mappings
        """
        def _classify_tactic(row):
            # Simple rule-based MITRE tactic classification
            if 'phishing' in str(row['event_type']).lower():
                return 'initial_access'
            elif 'escalation' in str(row['event_type']).lower():
                return 'privilege_escalation'
            elif 'persistence' in str(row['event_type']).lower():
                return 'persistence'
            return 'unknown'
        
        df['mitre_tactic'] = df.apply(_classify_tactic, axis=1)
        return df
    
    def generate_threat_report(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate comprehensive threat intelligence report
        
        Args:
            df (pd.DataFrame): Processed security log DataFrame
        
        Returns:
            Dict: Threat intelligence report
        """
        report = {
            'total_events': len(df),
            'anomalous_events': df['is_anomalous'].sum(),
            'mitre_tactic_breakdown': df['mitre_tactic'].value_counts().to_dict(),
            'top_source_ips': df['source_ip'].value_counts().head(5).to_dict(),
            'timestamp': datetime.now().isoformat()
        }
        
        return report
    
    def process_security_logs(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Comprehensive security log processing pipeline
        
        Args:
            log_data (List[Dict]): Raw security log entries
        
        Returns:
            Dict: Comprehensive threat intelligence report
        """
        try:
            # Process logs through analysis pipeline
            df = self.parse_security_logs(log_data)
            df = self.detect_anomalies(df)
            df = self.map_mitre_tactics(df)
            
            # Generate threat report
            threat_report = self.generate_threat_report(df)
            
            self.logger.info("Security log analysis completed successfully")
            return threat_report
        
        except Exception as e:
            self.logger.error(f"Security log processing failed: {e}")
            return {}

def main():
    # Example usage
    sample_logs = [
        {
            'timestamp': '2024-03-05T10:30:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.50',
            'source_port': 54321,
            'destination_port': 443,
            'packet_size': 1024,
            'event_type': 'potential_phishing'
        }
        # Add more sample log entries
    ]
    
    threat_analyzer = ThreatIntelligenceAnalyzer()
    report = threat_analyzer.process_security_logs(sample_logs)
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
