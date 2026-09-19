from datetime import datetime

MAX_ATTEMPTS = 4
TIME_WINDOW = 60
dico = {} # {ip_address: [username, attempts, first_attempt_time, first_attempt_date]}

def parse_log(line):
    log = {}
    date, time, event, *data  = line.strip().split(" ")

    log["date"] = date
    log["time"] = time
    log["event"] = event

    for element in data:
        name,value = element.split("=")
        log[name] = value

    return log

def detect_port_scan(log):
    return {"level": "WARNING", "event": "PORT_SCAN", "ip": log["ip"]}

def detect_bruteforce(log):

    if log["ip"] in dico:
    
        # Reset if the date is different or if the time difference exceeds the TIME_WINDOW
        if dico[log["ip"]][3] != log["date"] or ((datetime.strptime(log["time"], "%H:%M:%S") - datetime.strptime(dico[log["ip"]][2], "%H:%M:%S")).total_seconds() > TIME_WINDOW):
            dico[log["ip"]] = [log["user"], 1, log["time"], log["date"]]
        else:
            dico[log["ip"]][1] += 1

            # Check if the number of attempts exceeds MAX_ATTEMPTS
            if dico[log["ip"]][1] >= MAX_ATTEMPTS:
                return {"level": "ALERT", "event": "BRUTE_FORCE", "ip": log["ip"], "user": dico[log["ip"]][0], "attempts": dico[log["ip"]][1]}

    else:
        dico[log["ip"]] = [log["user"], 1, log["time"], log["date"]]


def display_alerts(alerts):
    for alert in alerts:
        print(f"[{alert['level']}] - {alert['event']} - IP: {alert['ip']}", end="")
        if alert['event'] == "BRUTE_FORCE":
            print(f" - User: {alert['user']} - Attempts: {alert['attempts']}")
        else:
            print()

def main():

    alerts = []

    with open("logs.txt","r") as f:
        lines = f.readlines()

    for line in lines:

        log = parse_log(line)
        
        if log["event"] == "LOGIN_FAILED":
            alert = detect_bruteforce(log)
            if alert is not None:
                alerts.append(alert)

        elif log["event"] == "PORT_SCAN":
            alert = detect_port_scan(log)
            if alert is not None:
                alerts.append(alert)
            
    display_alerts(alerts)

if __name__ == "__main__":
    main()