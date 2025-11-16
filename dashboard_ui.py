
"""
COMPLETE Mini IDS Dashboard - All in One File
No external templates needed!
"""

from flask import Flask, Response
from flask_socketio import SocketIO
import json
import time
from datetime import datetime
from collections import deque
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mini_ids_secret_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

class CompleteDashboard:
    def __init__(self):
        self.alerts = deque(maxlen=50)
        self.statistics = {
            'total_packets': 0,
            'total_alerts': 0,
            'alerts_by_severity': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
            'network_health': 100,
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        print("🎨 Complete IDS Dashboard Initialized: http://localhost:5000")

    def add_alert(self, alert_data):
        """Add new alert to dashboard"""
        try:
            self.alerts.append(alert_data)
            self.statistics['total_alerts'] += 1
            self.statistics['total_packets'] += 1
            
            severity = alert_data.get('severity', 'LOW')
            self.statistics['alerts_by_severity'][severity] = \
                self.statistics['alerts_by_severity'].get(severity, 0) + 1
            
            # Update network health
            alert_count = self.statistics['total_alerts']
            self.statistics['network_health'] = max(20, 100 - (alert_count * 2))
            
            # Send to all connected clients
            socketio.emit('new_alert', {
                'alert': alert_data,
                'statistics': self.statistics
            })
            
            print(f"📊 Dashboard: {alert_data.get('alert_type', 'Unknown')} from {alert_data.get('source_ip', 'Unknown')}")
            return True
        except Exception as e:
            print(f"❌ Dashboard error: {e}")
            return False

# Create global instance
dashboard = CompleteDashboard()

# HTML Template as string - NO EXTERNAL FILES NEEDED
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mini IDS Security Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        
        /* Header */
        .header {
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 25px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(45deg, #6366f1, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .status {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 8px 20px;
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 20px;
            font-size: 0.9em;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-icon { font-size: 2em; margin-bottom: 15px; opacity: 0.8; }
        .stat-number { font-size: 2.2em; font-weight: bold; margin: 10px 0; }
        .stat-packet { color: #6366f1; }
        .stat-alert { color: #ef4444; }
        .stat-threat { color: #f59e0b; }
        .stat-health { color: #10b981; }
        
        /* Alerts Section */
        .alerts-section {
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 25px;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .section-header h2 {
            font-size: 1.4em;
            background: linear-gradient(45deg, #6366f1, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .live-badge {
            background: #ef4444;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            animation: pulse 2s infinite;
        }
        .alert-item {
            background: rgba(255, 255, 255, 0.03);
            padding: 18px;
            margin: 12px 0;
            border-radius: 10px;
            border-left: 4px solid;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
        .alert-item:hover { background: rgba(255, 255, 255, 0.07); }
        .alert-low { border-left-color: #6366f1; }
        .alert-medium { border-left-color: #f59e0b; }
        .alert-high { border-left-color: #ef4444; }
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .alert-type { font-weight: bold; font-size: 1.1em; }
        .alert-severity {
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .severity-low { background: #6366f1; }
        .severity-medium { background: #f59e0b; color: #000; }
        .severity-high { background: #ef4444; }
        .alert-source { color: #94a3b8; font-size: 0.9em; margin-bottom: 5px; }
        .alert-desc { color: #cbd5e1; line-height: 1.4; }
        .alert-time { color: #64748b; font-size: 0.8em; margin-top: 8px; }
        
        /* Network Section */
        .network-section {
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .network-map {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .node {
            background: rgba(99, 102, 241, 0.1);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid rgba(99, 102, 241, 0.3);
            text-align: center;
        }
        .node-ip { font-weight: bold; color: #6366f1; }
        .node-threat { font-size: 0.8em; color: #94a3b8; }
        
        .btn {
            background: linear-gradient(45deg, #6366f1, #8b5cf6);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
        }
        .btn:hover { opacity: 0.9; }
        
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr; }
            .section-header { flex-direction: column; gap: 10px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Mini IDS Security Dashboard</h1>
            <div class="status">
                <div class="status-dot"></div>
                <span>LIVE MONITORING ACTIVE</span>
            </div>
        </div>

        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-network-wired"></i></div>
                <h3>Total Packets</h3>
                <div class="stat-number stat-packet" id="totalPackets">0</div>
                <p>Network Traffic</p>
            </div>
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-bell"></i></div>
                <h3>Security Alerts</h3>
                <div class="stat-number stat-alert" id="totalAlerts">0</div>
                <p>Threats Detected</p>
            </div>
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-bug"></i></div>
                <h3>Threat IPs</h3>
                <div class="stat-number stat-threat" id="threatIPs">0</div>
                <p>Malicious Sources</p>
            </div>
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-heartbeat"></i></div>
                <h3>Network Health</h3>
                <div class="stat-number stat-health" id="networkHealth">100%</div>
                <p>System Status</p>
            </div>
        </div>

        <!-- Alerts -->
        <div class="alerts-section">
            <div class="section-header">
                <h2><i class="fas fa-exclamation-triangle"></i> Live Security Alerts</h2>
                <div>
                    <span class="live-badge">REAL-TIME</span>
                    <button class="btn" onclick="clearAlerts()" style="margin-left: 10px;">
                        <i class="fas fa-trash"></i> Clear
                    </button>
                </div>
            </div>
            <div id="alertsList">
                <div class="alert-item">
                    <div style="text-align: center; color: #64748b; padding: 40px;">
                        <i class="fas fa-shield-alt" style="font-size: 3em; margin-bottom: 15px; opacity: 0.5;"></i>
                        <p>Monitoring network traffic... Waiting for alerts</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Network Map -->
        <div class="network-section">
            <div class="section-header">
                <h2><i class="fas fa-sitemap"></i> Network Activity</h2>
            </div>
            <div id="networkMap">
                <div style="text-align: center; color: #64748b; padding: 30px;">
                    <i class="fas fa-wifi" style="font-size: 2.5em; margin-bottom: 10px; opacity: 0.5;"></i>
                    <p>No network activity detected yet</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let socket = io();
        
        socket.on('connect', function() {
            console.log('✅ Connected to IDS Dashboard');
            updateStats();
        });
        
        socket.on('new_alert', function(data) {
            console.log('🚨 New alert:', data.alert);
            updateStats(data.statistics);
            addNewAlert(data.alert);
        });
        
        function updateStats(stats = null) {
            if (stats) {
                document.getElementById('totalPackets').textContent = stats.total_packets.toLocaleString();
                document.getElementById('totalAlerts').textContent = stats.total_alerts.toLocaleString();
                document.getElementById('threatIPs').textContent = Math.min(stats.total_alerts, 99);
                document.getElementById('networkHealth').textContent = Math.round(stats.network_health) + '%';
            }
        }
        
        function addNewAlert(alert) {
            const alertsList = document.getElementById('alertsList');
            
            // Remove welcome message if present
            if (alertsList.innerHTML.includes('Monitoring network traffic')) {
                alertsList.innerHTML = '';
            }
            
            const alertHTML = `
                <div class="alert-item alert-${alert.severity.toLowerCase()}">
                    <div class="alert-header">
                        <span class="alert-type">${alert.alert_type}</span>
                        <span class="alert-severity severity-${alert.severity.toLowerCase()}">
                            ${alert.severity}
                        </span>
                    </div>
                    <div class="alert-source">
                        <i class="fas fa-laptop"></i> Source: ${alert.source_ip}
                    </div>
                    <div class="alert-desc">
                        ${alert.description}
                    </div>
                    <div class="alert-time">
                        <i class="fas fa-clock"></i> ${alert.timestamp}
                    </div>
                </div>
            `;
            
            alertsList.innerHTML = alertHTML + alertsList.innerHTML;
            
            // Keep only last 10 alerts
            const alertItems = alertsList.getElementsByClassName('alert-item');
            if (alertItems.length > 10) {
                alertsList.removeChild(alertItems[alertItems.length - 1]);
            }
            
            // Show notification
            showNotification(`New ${alert.severity} alert from ${alert.source_ip}`);
        }
        
        function clearAlerts() {
            fetch('/clear-alerts', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('alertsList').innerHTML = `
                        <div class="alert-item">
                            <div style="text-align: center; color: #64748b; padding: 20px;">
                                <i class="fas fa-check-circle" style="color: #10b981;"></i>
                                <p>Alerts cleared successfully</p>
                            </div>
                        </div>
                    `;
                    showNotification('All alerts cleared');
                });
        }
        
        function showNotification(message) {
            // Simple notification
            console.log('📢 ' + message);
        }
        
        // Auto-refresh stats every 10 seconds
        setInterval(() => {
            fetch('/stats').then(r => r.json()).then(updateStats);
        }, 10000);
    </script>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    return Response(HTML_TEMPLATE, mimetype='text/html')

@app.route('/stats')
def get_stats():
    return jsonify(dashboard.statistics)

@app.route('/alerts')
def get_alerts():
    alerts_list = list(dashboard.alerts)
    return jsonify({
        'alerts': alerts_list[-20:],  # Last 20 alerts
        'total': len(alerts_list)
    })

@app.route('/clear-alerts', methods=['POST'])
def clear_alerts():
    dashboard.alerts.clear()
    dashboard.statistics['total_alerts'] = 0
    dashboard.statistics['alerts_by_severity'] = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
    dashboard.statistics['network_health'] = 100
    return jsonify({'status': 'success', 'message': 'Alerts cleared'})

def start_dashboard():
    """Start the dashboard server"""
    print("🚀 Starting Mini IDS Dashboard on http://localhost:5000")
    print("💡 Access the dashboard in your web browser!")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    start_dashboard()