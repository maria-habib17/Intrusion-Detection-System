

import threading
import time
from dashboard_ui import dashboard, start_dashboard
from ids_core_enhanced import EnhancedMiniIDS

def run_dashboard():
    """Run dashboard in background thread"""
    start_dashboard()

def run_ids():
    """Run the IDS"""
    print("🛡️ Starting Enhanced Mini IDS with Dashboard...")
    ids = EnhancedMiniIDS()
    ids.start_monitoring()

if __name__ == "__main__":
    # Start dashboard in background
    print("🎨 Starting Beautiful Dashboard...")
    dashboard_thread = threading.Thread(target=run_dashboard)
    dashboard_thread.daemon = True
    dashboard_thread.start()
    
    # Wait for dashboard to start
    print("⏳ Waiting for dashboard to initialize...")
    time.sleep(3)
    
    # Start IDS
    run_ids()