MAX_ATTEMPTS = 4
TIME_WINDOW = 60

def main():

    with open("logs.txt","r") as f:
        lines = f.readlines()

    # {ip_address: [username, attempts, first_attempt_time, first_attempt_date]}
    dico = {}
    for line in lines:
        date, time, event, username, ip_address = line.strip().split(" ")
        if event == "LOGIN_FAILED":
            if ip_address in dico:
                dico[ip_address][1] += 1
            else:
                dico[ip_address] = [username, 1, time, date]

    for x,y in dico.items():
        if y[1] >= MAX_ATTEMPTS:
            print("x"+str(y[1])+" [ALERT] " +y[0]+" from "+x+" has failed to login "+str(y[1])+" times since "+y[3]+" "+y[2])

    

if __name__ == "__main__":
    main()