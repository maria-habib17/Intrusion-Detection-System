from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading
import json
from datetime import datetime
import plotly.graph_objects as go
import plotly.utils

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

class RealTimeDashboard:
    def __init__(self, config):
        self.config = config
        self.alerts = []
        self.statistics = {
            'total_packets': 0,
            'alerts_by_type': {},
            'top_threats': [],
            'network_health': 100
        }
        self.setup_routes()
    
    def setup_routes(self):
        @app.route('/')
        def index():
            return render_template('dashboard.html')
        
        @app.route('/api/statistics')
        def get_statistics():
            return jsonify(self.statistics)
        
        @app.route('/api/alerts')
        def get_alerts():
            return jsonify(self.alerts[-50:])  # Last 50 alerts
        
        @app.route('/api/network_map')
        def get_network_map():
            return jsonify(self.generate_network_map())
    
    def generate_network_map(self):
        """Generate interactive network topology"""
        nodes = []
        links = []
        
        # Add detected hosts as nodes
        for alert in self.alerts[-20:]:  # Last 20 alerts
            nodes.append({
                'id': alert.get('source_ip', 'unknown'),
                'name': alert.get('source_ip', 'unknown'),
                'val': alert.get('severity_weight', 1),
                'color': self.get_severity_color(alert.get('severity', 'low'))
            })
            
            # Add connections
            if 'destination_ip' in alert:
                links.append({
                    'source': alert['source_ip'],
                    'target': alert['destination_ip'],
                    'width': alert.get('severity_weight', 1)
                })
        
        return {'nodes': nodes, 'links': links}
    
    def get_severity_color(self, severity):
        colors = {
            'low': '#00ff00',
            'medium': '#ffff00', 
            'high': '#ff0000',
            'critical': '#8b0000'
        }
        return colors.get(severity, '#cccccc')
    
    def update_dashboard(self, alert_data):
        """Update dashboard with new alert"""
        self.alerts.append(alert_data)
        
        # Update statistics
        self.statistics['total_packets'] += 1
        alert_type = alert_data.get('alert_type', 'unknown')
        self.statistics['alerts_by_type'][alert_type] = \
            self.statistics['alerts_by_type'].get(alert_type, 0) + 1
        
        # Send real-time update to connected clients
        socketio.emit('new_alert', {
            'alert': alert_data,
            'statistics': self.statistics,
            'timestamp': datetime.now().isoformat()
        })
    
    def generate_analytics_charts(self):
        """Generate Plotly charts for analytics"""
        # Alert trend chart
        times = [alert['timestamp'] for alert in self.alerts[-100:]]
        severities = [alert.get('severity_weight', 1) for alert in self.alerts[-100:]]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=times, 
            y=severities,
            mode='lines+markers',
            name='Alert Severity Trend'
        ))
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def run_dashboard(self):
        """Start the dashboard server"""
        print(f"🌐 Starting Web Dashboard on port {self.config['dashboard']['port']}")
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=self.config['dashboard']['port'],
            debug=False
        )