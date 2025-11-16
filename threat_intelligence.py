import requests
import json
import time
from datetime import datetime, timedelta
import hashlib
from cachetools import TTLCache

class ThreatIntelligenceEngine:
    def __init__(self, config):
        self.config = config
        self.cache = TTLCache(maxsize=1000, ttl=3600)  # 1 hour cache
        self.sources = config['threat_intelligence']['sources']
        self.api_keys = config['threat_intelligence']['api_keys']
        
    def check_ip_reputation(self, ip_address):
        """Check IP against multiple threat intelligence feeds"""
        cached_result = self.cache.get(ip_address)
        if cached_result:
            return cached_result
        
        reputation_score = 0
        threat_indicators = []
        confidence = 0
        
        # Check multiple sources
        if 'abuseipdb' in self.sources:
            abuse_result = self.check_abuseipdb(ip_address)
            reputation_score += abuse_result.get('score', 0)
            threat_indicators.extend(abuse_result.get('threats', []))
            confidence = max(confidence, abuse_result.get('confidence', 0))
        
        if 'virustotal' in self.sources:
            vt_result = self.check_virustotal(ip_address)
            reputation_score += vt_result.get('score', 0)
            threat_indicators.extend(vt_result.get('threats', []))
            confidence = max(confidence, vt_result.get('confidence', 0))
        
        if 'alienvault' in self.sources:
            otx_result = self.check_alienvault(ip_address)
            reputation_score += otx_result.get('score', 0)
            threat_indicators.extend(otx_result.get('threats', []))
        
        result = {
            'reputation_score': reputation_score,
            'threat_indicators': list(set(threat_indicators)),
            'confidence': confidence,
            'is_malicious': reputation_score > 50,  # Threshold
            'last_checked': datetime.now().isoformat()
        }
        
        self.cache[ip_address] = result
        return result
    
    def check_abuseipdb(self, ip_address):
        """Check IP against AbuseIPDB"""
        try:
            api_key = self.api_keys.get('abuseipdb')
            if not api_key:
                return {'score': 0, 'threats': [], 'confidence': 0}
                
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'score': data.get('abuseConfidenceScore', 0),
                    'threats': ['malicious'] if data.get('abuseConfidenceScore', 0) > 50 else [],
                    'confidence': data.get('abuseConfidenceScore', 0) / 100
                }
        except Exception as e:
            print(f"AbuseIPDB check failed: {e}")
        
        return {'score': 0, 'threats': [], 'confidence': 0}
    
    def check_virustotal(self, ip_address):
        """Check IP against VirusTotal"""
        try:
            api_key = self.api_keys.get('virustotal')
            if not api_key:
                return {'score': 0, 'threats': [], 'confidence': 0}
                
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {
                'x-apikey': api_key
            }
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()['data']
                attributes = data.get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious_count = last_analysis_stats.get('malicious', 0)
                total_engines = sum(last_analysis_stats.values())
                
                if total_engines > 0:
                    score = (malicious_count / total_engines) * 100
                    return {
                        'score': score,
                        'threats': ['malicious'] if malicious_count > 0 else [],
                        'confidence': malicious_count / total_engines if total_engines > 0 else 0
                    }
        except Exception as e:
            print(f"VirusTotal check failed: {e}")
        
        return {'score': 0, 'threats': [], 'confidence': 0}
    
    def check_alienvault(self, ip_address):
        """Check IP against AlienVault OTX"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                
                return {
                    'score': min(pulse_count * 10, 100),  # Scale pulse count to 0-100
                    'threats': ['malicious'] if pulse_count > 0 else [],
                    'confidence': min(pulse_count / 10, 1.0)  # Normalize confidence
                }
        except Exception as e:
            print(f"AlienVault check failed: {e}")
        
        return {'score': 0, 'threats': [], 'confidence': 0}