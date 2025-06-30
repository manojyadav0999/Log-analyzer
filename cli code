import csv
import os
from collections import Counter
from tkinter import Tk, filedialog


def parse_embedded_message(message):
    """Parse message field like XR-DEL!@DEL_usr:neo99=>/tmp/init.sock"""
    try:
        event_type = message.split("!@")[0].strip()
        details = message.split("=>")
        if len(details) == 2:
            user_part = details[0].split("_usr:")[-1]
            target_part = details[1]
        else:
            user_part, target_part = "-", "-"
    except:
        event_type, user_part, target_part = "-", "-", "-"
    return event_type.upper(), user_part.strip(), target_part.strip()


def extract_event_data(row):
    """Determine if row uses clear or embedded fields"""
    if 'Event Type' in row and 'User' in row and 'Target' in row:
        return row['Event Type'].upper(), row['User'], row['Target']
    elif 'message' in row:
        return parse_embedded_message(row['message'])
    else:
        return "-", "-", "-"


def analyze_forensics(csv_path, output_path):
    events = []
    users = set()
    connections, execs, file_mods, deletes, logs, shadows = [], [], [], [], [], []
    passwd_events, secure_scripts, xz_events, xrun_events = [], [], [], []

    with open(csv_path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_type, user, target = extract_event_data(row)
            timestamp = row.get('timestamp', row.get('Timestamp', ''))

            event = {
                'Timestamp': timestamp,
                'Event Type': event_type,
                'User': user,
                'Target': target
            }
            events.append(event)
            users.add(user)

            # Categorization
            if event_type == 'XR-CONN':
                connections.append(event)
            elif event_type == 'XR-EXEC':
                execs.append(event)
            elif event_type == 'XR-FILE':
                file_mods.append(event)
            elif event_type == 'XR-DEL':
                deletes.append(event)
            elif event_type == 'XR-LOG':
                logs.append(event)
            elif event_type == 'XR-SHDW':
                shadows.append(event)

            # Suspicious Targets
            if "/etc/passwd" in target:
                passwd_events.append(event)
            if "/opt/secure.shd" in target:
                secure_scripts.append(event)
            if "/bin/xz" in target:
                xz_events.append(event)
            if "/usr/lib/xrun.conf" in target:
                xrun_events.append(event)

    with open(output_path, "w", encoding='utf-8') as report:
        report.write("🛡️ FORENSIC EVENT ANALYSIS REPORT\n")
        report.write("=" * 50 + "\n\n")
        report.write(f"📁 Source File: {os.path.basename(csv_path)}\n")
        report.write(f"📊 Total Events: {len(events)}\n")
        report.write(f"👤 Users Involved: {', '.join([u for u in users if u != '-']) or 'N/A'}\n\n")

        report.write("🔑 EVENT TYPE SUMMARY\n")
        report.write("-" * 30 + "\n")
        report.write(f"XR-CONN : {len(connections)} connections\n")
        report.write(f"XR-EXEC : {len(execs)} executions\n")
        report.write(f"XR-FILE : {len(file_mods)} file modifications\n")
        report.write(f"XR-DEL  : {len(deletes)} deletions\n")
        report.write(f"XR-LOG  : {len(logs)} log accesses\n")
        report.write(f"XR-SHDW : {len(shadows)} shadow ops\n\n")

        report.write("🚩 SUSPICIOUS ACTIVITY DETECTED\n")
        report.write("-" * 30 + "\n")
        report.write(f"- /etc/passwd tampered: {len(passwd_events)} events\n")
        report.write(f"- Secure script executed: {len(secure_scripts)} events\n")
        report.write(f"- /bin/xz involved: {len(xz_events)} events\n")
        report.write(f"- Shadow processes killed: {len(shadows)} entries\n")
        report.write(f"- Remote connections: {len(connections)} events\n\n")

        report.write("👥 USER BEHAVIOR SNAPSHOT\n")
        report.write("-" * 30 + "\n")
        for user in sorted(users):
            if user != '-':
                count = sum(1 for e in events if e['User'] == user)
                report.write(f"- {user}: {count} actions\n")
        report.write("\n")

        report.write("🔄 PROBABLE ATTACK CHAIN\n")
        report.write("-" * 30 + "\n")
        report.write("1. Initial Access: Remote connection from external IPs\n")
        report.write("2. Privilege Escalation: /etc/passwd modified/deleted\n")
        report.write("3. Payload Execution: /opt/secure.shd, /bin/xz executed\n")
        report.write("4. Defense Evasion: Security processes terminated via XR-SHDW\n")
        report.write("5. Cleanup: Files deleted to cover tracks\n\n")

        report.write("📘 RECOMMENDATIONS\n")
        report.write("-" * 30 + "\n")
        report.write("• Isolate suspicious users immediately\n")
        report.write("• Review IP traffic and block malicious sources\n")
        report.write("• Check system file integrity (/etc/passwd, /bin/xz)\n")
        report.write("• Scan for rootkits and persistent malware\n")
        report.write("• Investigate /usr/lib and /opt for backdoors\n\n")

        report.write("✅ End of Report\n")

    print(f"✅ Forensic report saved as: {output_path}")


# 🔁 Universal file picker
if __name__ == "__main__":
    Tk().withdraw()

    selected_file = filedialog.askopenfilename(
        title="📄 Select parsed forensic CSV file",
        filetypes=[("CSV files", "*.csv")]
    )
    if not selected_file:
        print("❌ No file selected.")
        exit()

    output_dir = filedialog.askdirectory(title="📂 Select output folder for report")
    if not output_dir:
        print("❌ No output folder selected.")
        exit()

    output_path = os.path.join(output_dir, "universal_forensic_report.txt")
    analyze_forensics(selected_file, output_path)

