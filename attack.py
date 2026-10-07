import socket
import subprocess
import time

print("Starting simulated Reverse Shell...")
print("Spamming network sockets, system commands, and sensitive file reads.")
print("Check your AI Process Monitor. Press Ctrl+C to stop.")

while True:
    try:
        # 1. Simulate a network scan or reverse shell connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        s.connect_ex(('127.0.0.1', 4444))
        s.close()

        # 2. Simulate executing malicious payload commands
        subprocess.run(["whoami"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 3. Simulate probing the shadow password file
        try:
            with open("/etc/shadow", "r") as f:
                pass
        except PermissionError:
            pass

        # 4. Rapid loop to create a dense n-gram anomaly within the 2-second strace window
        time.sleep(0.05)
        
    except KeyboardInterrupt:
        print("\nSimulation stopped.")
        break
    except Exception:
        pass
