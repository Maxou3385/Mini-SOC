from datetime import datetime

MAX_ATTEMPTS = 4
TIME_WINDOW = 60
dico = {} # {ip_address: [username, attempts, first_attempt_time, first_attempt_date]}

def main():

    with open("logs.txt","r") as f:
        lines = f.readlines()

    for line in lines:

        date, time, event, *data = line.strip().split(" ")
        
        if event == "LOGIN_FAILED":

            username, ip_address = data
            if ip_address in dico:

                # Reset if the date is different or if the time difference exceeds the TIME_WINDOW
                if dico[ip_address][3] != date or ((datetime.strptime(time, "%H:%M:%S") - datetime.strptime(dico[ip_address][2], "%H:%M:%S")).total_seconds() > TIME_WINDOW):
                    dico[ip_address] = [username, 1, time, date]
                else:
                    dico[ip_address][1] += 1
                    # Check if the number of attempts exceeds MAX_ATTEMPTS
                    if dico[ip_address][1] >= MAX_ATTEMPTS:
                        print("[ALERT] " +dico[ip_address][0]+" from "+ip_address+" has failed to login "+str(dico[ip_address][1])+" times since "+dico[ip_address][3]+" "+dico[ip_address][2])
            else:
                dico[ip_address] = [username, 1, time, date]

        if event == "PORT_SCAN":

            ip_address, port = data
            print("[WARNING] Port scan detected from "+ip_address)

if __name__ == "__main__":
    main()