
from nids_engine import NIDSEngine
from datetime import datetime


def display_banner():

    print("\n")
    print("=" * 55)
    print("       PYTHON NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 55)

    print("       Network Security Monitoring System")
    print("=" * 55)


def display_menu():

    print("\n============== MAIN MENU ==============")

    print("1. Monitor Network Event")
    print("2. Generate Test Events")
    print("3. View Statistics")
    print("4. Block Suspicious IP")
    print("5. View Blocked IPs")
    print("6. Exit")

    print("=" * 39)


def monitor_event(engine):

    print("\n========== NETWORK EVENT MONITORING ==========")

    ip = input("Enter Source IP Address: ").strip()

    try:
        port = int(input("Enter Destination Port: "))

    except ValueError:
        print("\n[ERROR] Port must be a number.")
        return

    status, alert = engine.process_event(ip, port)

    print("\n-------------- EVENT RESULT --------------")

    print("Source IP       :", ip)
    print("Destination Port:", port)
    print("Timestamp       :", datetime.now().strftime("%H:%M:%S"))
    print("Status          :", status)
    print("Security Alert  :", alert)

    if status == "ATTACK":

        print("\n[!!!] SECURITY ALERT: POSSIBLE ATTACK DETECTED!")

    elif status == "WARNING":

        print("\n[WARNING] Suspicious activity observed.")

    elif status == "NORMAL":

        print("\n[OK] Network activity is normal.")

    elif status == "BLOCKED":

        print("\n[BLOCKED] This IP is already blocked.")

    else:

        print("\n[ERROR]", alert)

    print("------------------------------------------")


def generate_test_events(engine):

    print("\n========== TEST EVENT GENERATOR ==========")

    test_ip = "192.168.1.200"

    test_ports = [21, 22, 23, 80, 443]

    print("Generating port scan simulation...")

    for port in test_ports:

        status, alert = engine.process_event(test_ip, port)

        print(
            f"IP: {test_ip} | Port: {port} | "
            f"Status: {status} | Alert: {alert}"
        )

    print("\nTest completed.")


def block_suspicious_ip(engine):

    print("\n========== IP BLOCKING ==========")

    ip = input("Enter IP address to block: ").strip()

    if engine.block_ip(ip):

        print(f"\n[OK] {ip} added to simulated block list.")

    else:

        print("\n[ERROR] Invalid IP address.")


def main():

    engine = NIDSEngine()

    display_banner()

    while True:

        display_menu()

        choice = input("Enter your choice (1-6): ").strip()

        if choice == "1":

            monitor_event(engine)

        elif choice == "2":

            generate_test_events(engine)

        elif choice == "3":

            engine.show_statistics()

        elif choice == "4":

            block_suspicious_ip(engine)

        elif choice == "5":

            engine.show_blocked_ips()

        elif choice == "6":

            print("\nShutting down NIDS...")

            engine.show_statistics()

            print("\nThank you for using Python NIDS!")

            break

        else:

            print("\n[ERROR] Invalid choice. Try again.")


if __name__ == "__main__":

    main()
