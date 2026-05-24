"""
Machine Learning Anomaly Detector
Detects potential zero-day attacks using anomaly detection.
"""

import logging
import numpy as np
from typing import Dict, List, Optional, Tuple
from collections import Counter
from datetime import datetime, timedelta

logger = logging.getLogger('honeypot')


class MLAnomalyDetector:
    """
    Machine learning-based anomaly detector for zero-day attacks.
    Uses Isolation Forest-like approach for detecting unusual patterns.
    """
    
    def __init__(self):
        self.baseline_data = {
            'commands': Counter(),
            'command_lengths': [],
            'login_patterns': {},
            'connection_intervals': [],
            'protocol_distribution': Counter(),
        }
        self.is_trained = False
        self.anomaly_threshold = 0.7
    
    def extract_features(self, data: Dict) -> np.ndarray:
        """Extract numerical features from attack data."""
        features = []
        
        # Command length feature
        command = data.get('command', '')
        features.append(len(command))
        
        # Special character ratio
        if command:
            special_chars = sum(1 for c in command if not c.isalnum() and c != ' ')
            features.append(special_chars / len(command))
        else:
            features.append(0)
        
        # Time-based features
        timestamp = data.get('timestamp', datetime.now())
        if isinstance(timestamp, datetime):
            features.append(timestamp.hour)
            features.append(timestamp.weekday())
        else:
            features.append(12)  # Default
            features.append(3)
        
        # Connection count from IP (if available)
        features.append(data.get('connection_count', 1))
        
        # Login attempt count
        features.append(data.get('login_attempts', 0))
        
        # Credential entropy (unusual passwords)
        password = data.get('password', '')
        if password:
            char_freq = Counter(password)
            entropy = -sum((f/len(password)) * np.log2(f/len(password)) 
                          for f in char_freq.values() if f > 0)
            features.append(entropy)
        else:
            features.append(0)
        
        return np.array(features)
    
    def calculate_anomaly_score(self, features: np.ndarray) -> float:
        """
        Calculate anomaly score using statistical methods.
        Higher score indicates more anomalous behavior.
        """
        if not self.is_trained or len(self.baseline_data['command_lengths']) < 10:
            # Not enough data, use heuristics
            return self.heuristic_score(features)
        
        score = 0.0
        weight_sum = 0
        
        # Command length anomaly
        if self.baseline_data['command_lengths']:
            mean_len = np.mean(self.baseline_data['command_lengths'])
            std_len = np.std(self.baseline_data['command_lengths']) or 1
            z_score = abs(features[0] - mean_len) / std_len
            score += min(z_score / 3, 1.0) * 0.3
            weight_sum += 0.3
        
        # Special character ratio anomaly
        if features[1] > 0.4:  # More than 40% special chars
            score += features[1] * 0.3
            weight_sum += 0.3
        
        # Time anomaly (activity during unusual hours)
        hour = features[2]
        if hour < 6 or hour > 22:  # Night time
            score += 0.2
            weight_sum += 0.2
        
        # High connection count
        if features[4] > 10:
            score += min(features[4] / 100, 0.3)
            weight_sum += 0.3
        
        # High entropy password
        if features[6] > 4:  # High entropy
            score += 0.2
            weight_sum += 0.2
        
        if weight_sum > 0:
            return score / weight_sum
        return 0.5
    
    def heuristic_score(self, features: np.ndarray) -> float:
        """Calculate anomaly score using heuristics when not enough training data."""
        score = 0.0
        
        # Very long commands
        if features[0] > 200:
            score += 0.3
        
        # High special character ratio
        if features[1] > 0.5:
            score += 0.3
        
        # Multiple login attempts
        if len(features) > 5 and features[5] > 5:
            score += 0.2
        
        # High entropy password
        if len(features) > 6 and features[6] > 4.5:
            score += 0.2
        
        return min(score, 1.0)
    
    def update_baseline(self, data: Dict):
        """Update baseline with new data."""
        command = data.get('command', '')
        if command:
            self.baseline_data['commands'][command[:50]] += 1
            self.baseline_data['command_lengths'].append(len(command))
            
            # Keep only recent data
            if len(self.baseline_data['command_lengths']) > 10000:
                self.baseline_data['command_lengths'] = self.baseline_data['command_lengths'][-5000:]
        
        protocol = data.get('protocol', 'UNKNOWN')
        self.baseline_data['protocol_distribution'][protocol] += 1
        
        if len(self.baseline_data['command_lengths']) >= 100:
            self.is_trained = True
    
    def detect(self, data: Dict) -> Dict:
        """
        Detect if the given data represents anomalous behavior.
        Returns detection results with score and classification.
        """
        features = self.extract_features(data)
        score = self.calculate_anomaly_score(features)
        
        # Update baseline
        self.update_baseline(data)
        
        is_anomaly = score >= self.anomaly_threshold
        
        # Determine severity
        if score >= 0.9:
            severity = 'CRITICAL'
        elif score >= 0.8:
            severity = 'HIGH'
        elif score >= 0.7:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': round(score, 3),
            'severity': severity,
            'potential_zero_day': is_anomaly and score >= 0.85,
            'features': features.tolist(),
            'confidence': 'HIGH' if self.is_trained else 'LOW',
        }
    
    def analyze_pattern_sequence(self, commands: List[str]) -> Dict:
        """Analyze a sequence of commands for unusual patterns."""
        if len(commands) < 3:
            return {'is_suspicious': False, 'reason': 'Not enough commands'}
        
        # Check for reconnaissance patterns
        recon_commands = ['ls', 'pwd', 'whoami', 'id', 'uname', 'cat /etc/passwd']
        recon_count = sum(1 for cmd in commands if any(r in cmd.lower() for r in recon_commands))
        
        # Check for privilege escalation attempts
        priv_commands = ['sudo', 'su ', 'chmod 777', 'chown']
        priv_count = sum(1 for cmd in commands if any(p in cmd.lower() for p in priv_commands))
        
        # Check for data exfiltration
        exfil_commands = ['wget', 'curl', 'scp', 'ftp', 'nc ']
        exfil_count = sum(1 for cmd in commands if any(e in cmd.lower() for e in exfil_commands))
        
        patterns_found = []
        
        if recon_count >= 3:
            patterns_found.append('RECONNAISSANCE')
        if priv_count >= 1:
            patterns_found.append('PRIVILEGE_ESCALATION')
        if exfil_count >= 1:
            patterns_found.append('DATA_EXFILTRATION')
        
        # Kill chain detection
        kill_chain_stages = []
        if recon_count > 0:
            kill_chain_stages.append('RECONNAISSANCE')
        if priv_count > 0:
            kill_chain_stages.append('PRIVILEGE_ESCALATION')
        if exfil_count > 0:
            kill_chain_stages.append('EXFILTRATION')
        
        return {
            'is_suspicious': len(patterns_found) > 0,
            'patterns': patterns_found,
            'kill_chain_stages': kill_chain_stages,
            'recon_commands': recon_count,
            'priv_commands': priv_count,
            'exfil_commands': exfil_count,
            'total_commands': len(commands),
            'risk_level': 'HIGH' if len(patterns_found) >= 2 else ('MEDIUM' if patterns_found else 'LOW'),
        }


# Global instance
anomaly_detector = MLAnomalyDetector()
