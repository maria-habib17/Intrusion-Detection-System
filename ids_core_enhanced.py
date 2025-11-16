#!/usr/bin/env python3
"""
ENHANCED Mini Intrusion Detection System (IDS)
Cybersecurity Student Project - Advanced Version
"""

import json
import time
import logging
import os
from datetime import datetime
from collections import defaultdict, deque
import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import colorama
from colorama import Fore, Style
from dashboard_ui import dashboard

# Initialize colorama for colored output
colorama.init(autoreset=True)

class EnhancedMiniIDS:
    def __init__(self, config_file="config_enhanced.json"):
        """
        Initialize the Enhanced Mini IDS
        """
        self.load_config(config_file)
        self.setup_logging()
        
        # Advanced data structures
        self.connection_attempts = defaultdict(lambda: defaultdict(int))
        self.syn_packets = defaultdict(lambda: deque(maxlen=1000))
        self.failed_connections = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_attempts = defaultdict(lambda: set())
        self.packet_count = defaultdict(int)
        self.behavior_profiles = defaultdict(dict)
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'suspicious_events': 0,
            'alerts_triggered': 0,
            'ai_detections': 0,
            'start_time': datetime.now()
        }
        
        print(Fore.GREEN + "🚀 ENHANCED Mini IDS Started Successfully!")
        print(Fore.CYAN + "🌟 Advanced Features:")
        print(Fore.CYAN + "   - AI-Powered Anomaly Detection")
        print(Fore.CYAN + "   - Behavioral Analysis")
        print(Fore.CYAN + "   - Deep Packet Inspection")
        print(Fore.CYAN + "   - Multi-Layer Detection")
    
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(Fore.YELLOW + "⚠️  Config file not found. Using default configuration.")
            self.config = {
                "interface": None,
                "max_packets_per_second": 100,
                "whitelist_ips": ["127.0.0.1"],
                "ai_enabled": True,
                "deep_packet_inspection": True,
                "detection_rules": {
                    "port_scan": {"enabled": True, "max_ports_per_minute": 15, "alert_threshold": 10},
                    "syn_flood": {"enabled": True, "max_syn_per_second": 25, "alert_threshold": 20},
                    "failed_connections": {"enabled": True, "max_failed_per_minute": 8, "alert_threshold": 5},
                    "suspicious_ports": {"enabled": True, "ports": [4444, 31337, 12345, 666, 1337, 9999]},
                    "behavioral_analysis": {"enabled": True, "learning_period": 300}
                },
                "logging": {
                    "log_file": "logs/enhanced_ids_log.csv",
                    "console_alerts": True,
                    "log_level": "INFO"
                }
            }
    
    def setup_logging(self):
        """Setup enhanced logging system"""
        log_file = self.config['logging']['log_file']
        
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, self.config['logging']['log_level']),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('EnhancedMiniIDS')
    
    def is_whitelisted(self, ip):
        """Check if IP is in whitelist"""
        return ip in self.config['whitelist_ips']
    
    def ai_analyze_behavior(self, src_ip, packet_data):
        """AI-powered behavioral analysis"""
        if not self.config.get('ai_enabled', True):
            return {'anomaly_score': 0, 'is_anomaly': False}
        
        # Initialize behavior profile
        if src_ip not in self.behavior_profiles:
            self.behavior_profiles[src_ip] = {
                'packet_sizes': deque(maxlen=100),
                'ports_accessed': set(),
                'protocols_used': set(),
                'packet_rate': deque(maxlen=50),
                'first_seen': time.time(),
                'last_seen': time.time()
            }
        
        profile = self.behavior_profiles[src_ip]
        profile['last_seen'] = time.time()
        
        # Simple anomaly detection based on packet size distribution
        if hasattr(packet_data, 'len'):
            packet_size = packet_data.len
            profile['packet_sizes'].append(packet_size)
            
            # Calculate if current packet size is anomaly
            if len(profile['packet_sizes']) > 10:
                avg_size = sum(profile['packet_sizes']) / len(profile['packet_sizes'])
                std_size = (sum((x - avg_size) ** 2 for x in profile['packet_sizes']) / len(profile['packet_sizes'])) ** 0.5
                
                if std_size > 0:
                    z_score = abs(packet_size - avg_size) / std_size
                    anomaly_score = min(z_score / 3.0, 1.0)  # Normalize to 0-1
                    
                    return {
                        'anomaly_score': anomaly_score,
                        'is_anomaly': z_score > 2.0,  # 2 standard deviations
                        'confidence': anomaly_score
                    }
        
        return {'anomaly_score': 0, 'is_anomaly': False, 'confidence': 0}
    
    def deep_packet_inspection(self, packet):
        """Analyze packet payload for suspicious content"""
        if not self.config.get('deep_packet_inspection', True):
            return {'suspicious': False, 'patterns_found': []}
        
        suspicious_patterns = {
            b'exec': 'Code Execution',
            b'eval': 'Code Evaluation',
            b'base64_decode': 'Base64 Encoding',
            b'cmd.exe': 'Windows Command',
            b'/bin/sh': 'Shell Command',
            b'union select': 'SQL Injection',
            b'<script>': 'JavaScript',
            b'javascript:': 'JavaScript URL',
            b'powershell': 'PowerShell',
            b'whoami': 'System Discovery'
        }
        
        patterns_found = []
        
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            payload_lower = payload.lower()
            
            for pattern, description in suspicious_patterns.items():
                if pattern in payload_lower:
                    patterns_found.append(description)
        
        return {
            'suspicious': len(patterns_found) > 0,
            'patterns_found': patterns_found
        }
    
    def enhanced_packet_handler(self, packet):
        """
        Enhanced packet processing with AI and DPI
        """
        if not packet.haslayer(IP):
            return
        
        self.stats['total_packets'] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Skip whitelisted IPs
        if self.is_whitelisted(src_ip):
            return
        
        # Multi-layer analysis
        ai_analysis = self.ai_analyze_behavior(src_ip, packet)
        dpi_analysis = self.deep_packet_inspection(packet)
        
        # Process different protocol types
        if packet.haslayer(TCP):
            self.process_tcp_packet(packet, src_ip, dst_ip, ai_analysis, dpi_analysis)
        elif packet.haslayer(UDP):
            self.process_udp_packet(packet, src_ip, dst_ip, ai_analysis, dpi_analysis)
        elif packet.haslayer(ICMP):
            self.process_icmp_packet(packet, src_ip, dst_ip, ai_analysis)
        
        # Clean old data periodically
        if self.stats['total_packets'] % 1000 == 0:
            self.clean_old_data()
    
    def process_tcp_packet(self, packet, src_ip, dst_ip, ai_analysis, dpi_analysis):
        """Enhanced TCP packet processing"""
        tcp_layer = packet[TCP]
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = tcp_layer.flags
        
        current_time = time.time()
        
        # SYN Flood Detection
        if self.config['detection_rules']['syn_flood']['enabled']:
            if flags == 'S':  # SYN packet
                self.syn_packets[src_ip].append(current_time)
                self.detect_syn_flood(src_ip)
        
        # Port Scan Detection
        if self.config['detection_rules']['port_scan']['enabled']:
            if flags == 'S':  # SYN packet
                self.port_scan_attempts[src_ip].add(dport)
                self.detect_port_scan(src_ip)
        
        # Failed Connections Detection
        if self.config['detection_rules']['failed_connections']['enabled']:
            if flags in ['R', 'RA']:  # RST packet
                self.failed_connections[src_ip].append(current_time)
                self.detect_failed_connections(src_ip)
        
        # Suspicious Ports Detection
        if self.config['detection_rules']['suspicious_ports']['enabled']:
            suspicious_ports = self.config['detection_rules']['suspicious_ports']['ports']
            if dport in suspicious_ports:
                self.alert_suspicious_port(src_ip, dst_ip, dport)
        
        # AI Behavioral Alert
        if ai_analysis['is_anomaly']:
            self.stats['ai_detections'] += 1
            self.trigger_enhanced_alert(
                "AI Behavioral Anomaly",
                f"Unusual traffic pattern from {src_ip} (confidence: {ai_analysis['confidence']:.2f})",
                src_ip,
                severity="MEDIUM",
                ai_confidence=ai_analysis['confidence']
            )
        
        # Deep Packet Inspection Alert
        if dpi_analysis['suspicious']:
            self.trigger_enhanced_alert(
                "Suspicious Payload Detected",
                f"Malicious patterns in payload from {src_ip}: {', '.join(dpi_analysis['patterns_found'])}",
                src_ip,
                severity="HIGH",
                patterns=dpi_analysis['patterns_found']
            )
    
    def process_udp_packet(self, packet, src_ip, dst_ip, ai_analysis, dpi_analysis):
        """Process UDP packets"""
        udp_layer = packet[UDP]
        dport = udp_layer.dport
        
        # Suspicious UDP ports
        if self.config['detection_rules']['suspicious_ports']['enabled']:
            suspicious_ports = self.config['detection_rules']['suspicious_ports']['ports']
            if dport in suspicious_ports:
                self.alert_suspicious_port(src_ip, dst_ip, dport, "UDP")
    
    def process_icmp_packet(self, packet, src_ip, dst_ip, ai_analysis):
        """Process ICMP packets"""
        # ICMP flood detection
        self.packet_count[src_ip] += 1
        if self.packet_count[src_ip] > 50:  # Threshold for ICMP flood
            self.alert_icmp_flood(src_ip)
    
    def detect_syn_flood(self, src_ip):
        """Enhanced SYN flood detection"""
        window = self.config['detection_rules']['syn_flood']['max_syn_per_second']
        current_time = time.time()
        
        # Remove old SYN packets
        self.syn_packets[src_ip] = deque(
            [t for t in self.syn_packets[src_ip] if current_time - t < 1],
            maxlen=1000
        )
        
        if len(self.syn_packets[src_ip]) > window:
            self.trigger_enhanced_alert(
                "SYN Flood Attack",
                f"High rate of SYN packets from {src_ip} ({len(self.syn_packets[src_ip])} packets/sec)",
                src_ip,
                severity="HIGH"
            )
            self.syn_packets[src_ip].clear()
    
    def detect_port_scan(self, src_ip):
        """Enhanced port scan detection"""
        max_ports = self.config['detection_rules']['port_scan']['max_ports_per_minute']
        
        if len(self.port_scan_attempts[src_ip]) > max_ports:
            ports_scanned = len(self.port_scan_attempts[src_ip])
            self.trigger_enhanced_alert(
                "Port Scanning Detected",
                f"Multiple port connection attempts from {src_ip} ({ports_scanned} unique ports)",
                src_ip,
                severity="MEDIUM"
            )
            self.port_scan_attempts[src_ip].clear()
    
    def detect_failed_connections(self, src_ip):
        """Enhanced failed connection detection"""
        window = self.config['detection_rules']['failed_connections']['max_failed_per_minute']
        current_time = time.time()
        
        # Remove old failed connections
        self.failed_connections[src_ip] = deque(
            [t for t in self.failed_connections[src_ip] if current_time - t < 60],
            maxlen=100
        )
        
        if len(self.failed_connections[src_ip]) > window:
            self.trigger_enhanced_alert(
                "Multiple Failed Connections",
                f"Suspicious connection failures from {src_ip} ({len(self.failed_connections[src_ip])} failures/min)",
                src_ip,
                severity="LOW"
            )
    
    def alert_suspicious_port(self, src_ip, dst_ip, port, protocol="TCP"):
        """Alert on suspicious port connections"""
        self.trigger_enhanced_alert(
            f"Suspicious {protocol} Port",
            f"Connection to known suspicious port {port} from {src_ip} to {dst_ip}",
            src_ip,
            severity="MEDIUM"
        )
    
    def alert_icmp_flood(self, src_ip):
        """Alert on ICMP flood"""
        self.trigger_enhanced_alert(
            "ICMP Flood Suspected",
            f"High rate of ICMP packets from {src_ip} ({self.packet_count[src_ip]} packets)",
            src_ip,
            severity="MEDIUM"
        )
    
    def trigger_enhanced_alert(self, alert_type, description, source_ip, severity="LOW", **kwargs):
        """
        Enhanced alerting system with additional context
        """
        self.stats['alerts_triggered'] += 1
        self.stats['suspicious_events'] += 1
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Color coding based on severity
        severity_colors = {
            "LOW": Fore.BLUE,
            "MEDIUM": Fore.YELLOW,
            "HIGH": Fore.RED
        }
        
        color = severity_colors.get(severity, Fore.WHITE)
        
        # Enhanced console alert
        if self.config['logging']['console_alerts']:
            print(f"\n{color}🚨 ENHANCED ALERT [{severity}] {alert_type}")
            print(f"{color}📡 Source: {source_ip}")
            print(f"{color}📝 Description: {description}")
            
            # Additional context from AI/DPI
            if 'ai_confidence' in kwargs:
                print(f"{color}🤖 AI Confidence: {kwargs['ai_confidence']:.2f}")
            if 'patterns' in kwargs:
                print(f"{color}🔍 Malicious Patterns: {', '.join(kwargs['patterns'])}")
                
            print(f"{color}⏰ Time: {timestamp}")
            print("-" * 60)
        
        # Create alert data for dashboard
        alert_data = {
            'timestamp': timestamp,
            'alert_type': alert_type,
            'source_ip': source_ip,
            'destination_ip': kwargs.get('destination_ip', 'local'),
            'description': description,
            'severity': severity,
            'ai_confidence': kwargs.get('ai_confidence', 0),
            'patterns': kwargs.get('patterns', [])
        }
        
        # Send to dashboard
        try:
            dashboard.add_alert(alert_data)
            print(f"📊 Alert sent to dashboard: {alert_type}")
        except Exception as e:
            print(f"⚠️ Dashboard update failed: {e}")
        
        # Enhanced log entry
        log_entry = {
            'timestamp': timestamp,
            'alert_type': alert_type,
            'source_ip': source_ip,
            'description': description,
            'severity': severity,
            **kwargs
        }
        
        self.logger.warning(f"{alert_type} - {description} - Source: {source_ip}")
        self.save_to_csv(log_entry)
    
    def save_to_csv(self, log_entry):
        """Save enhanced alert to CSV"""
        csv_file = self.config['logging']['log_file']
        df = pd.DataFrame([log_entry])
        
        try:
            existing_df = pd.read_csv(csv_file)
            updated_df = pd.concat([existing_df, df], ignore_index=True)
            updated_df.to_csv(csv_file, index=False)
        except FileNotFoundError:
            df.to_csv(csv_file, index=False)
    
    def clean_old_data(self):
        """Clean old data to prevent memory leaks"""
        current_time = time.time()
        
        # Clean old behavior profiles (older than 1 hour)
        expired_ips = []
        for ip, profile in self.behavior_profiles.items():
            if current_time - profile['last_seen'] > 3600:  # 1 hour
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.behavior_profiles[ip]
    
    def print_enhanced_stats(self):
        """Print enhanced statistics"""
        runtime = datetime.now() - self.stats['start_time']
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "📊 ENHANCED IDS - RUNTIME STATISTICS")
        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + f"⏰ Runtime: {runtime}")
        print(Fore.GREEN + f"📦 Packets Processed: {self.stats['total_packets']}")
        print(Fore.YELLOW + f"🚨 Alerts Triggered: {self.stats['alerts_triggered']}")
        print(Fore.YELLOW + f"🤖 AI Detections: {self.stats['ai_detections']}")
        print(Fore.YELLOW + f"⚠️  Suspicious Events: {self.stats['suspicious_events']}")
        print(Fore.CYAN + "=" * 60)
    
    def start_monitoring(self, interface=None):
        """
        Start enhanced monitoring
        """
        print(Fore.GREEN + "🎯 Starting advanced network monitoring...")
        print(Fore.YELLOW + "Press Ctrl+C to stop monitoring")
        
        try:
            sniff(
                prn=self.enhanced_packet_handler,
                iface=interface or self.config['interface'],
                store=0
            )
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n🛑 Stopping Enhanced IDS...")
            self.print_enhanced_stats()
        except Exception as e:
            print(Fore.RED + f"❌ Error: {e}")
            self.print_enhanced_stats()

def main():
    """Main function to run the Enhanced IDS"""
    print(Fore.CYAN + """
    🚀 ENHANCED Mini Intrusion Detection System (IDS)
    🔥 Advanced Cybersecurity Project
    🤖 AI + Behavioral Analysis + Deep Packet Inspection
    """)
    
    try:
        enhanced_ids = EnhancedMiniIDS()
        enhanced_ids.start_monitoring()
    except PermissionError:
        print(Fore.RED + "❌ Permission denied. Run with sudo/administrator privileges.")
    except Exception as e:
        print(Fore.RED + f"❌ Failed to start Enhanced IDS: {e}")

if __name__ == "__main__":
    main()