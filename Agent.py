import pandas as pd
from sklearn.ensemble import IsolationForest
import os
from datetime import datetime

print("🔁 Starting AI Cyber Agent Monitoring...\n")

# Step 1: Load the data
data = pd.read_csv("login_logs.csv")

print(f"🔍 Scanning {len(data)} log entries...\n")

# Step 2: Select features for training
features = data[["login_attempts", "process_count", "download_MB"]]

# Step 3: Train Isolation Forest
model = IsolationForest(contamination=0.3)
model.fit(features)

# Step 4: Predict anomalies
data["prediction"] = model.predict(features)

# Step 5: Process each row
threats = []
safe_logs = []

for index, row in data.iterrows():
    log = {
        "ip_address": row["ip_address"],
        "time": row["time"],
        "status": "SAFE" if row["prediction"] == 1 else "THREAT"
    }

    if row["prediction"] == -1:
        print(f"⚠️ ALERT: Suspicious login from {row['ip_address']} at {row['time']}")
        print(f"🚫 Blocking IP {row['ip_address']} (Simulated)\n")
        threats.append(log)
    else:
        print(f"✅ Safe login from {row['ip_address']} at {row['time']}")
        safe_logs.append(log)

# Step 6: Save threats to threat_log.csv
if threats:
    threat_df = pd.DataFrame(threats)
    if os.path.exists("threat_log.csv"):
        threat_df.to_csv("threat_log.csv", mode='a', header=False, index=False)
    else:
        threat_df.to_csv("threat_log.csv", index=False)
    print("\n📝 Threats saved to threat_log.csv")
else:
    print("\n✅ No new threats found")

# Step 7: Save daily report with all entries
report = threats + safe_logs
report_df = pd.DataFrame(report)
date_str = datetime.now().strftime("%Y%m%d")
report_filename = f"daily_report_{date_str}.csv"
report_df.to_csv(report_filename, index=False)
print(f"📊 Daily summary saved as {report_filename}\n")
