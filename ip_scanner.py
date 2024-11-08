import socket
import ipaddress
import csv
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

# Configure logging
logging.basicConfig(filename="scan_log.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# Validate IP address
def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        logging.error(f"Invalid IP address: {ip}")
        return False


# Log results to CSV
def log_result(ip, hostname, open_ports):
    with open("scan_results.csv", "a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([ip, hostname, ", ".join([f"Port {port} ({banner})" for port, banner in open_ports])])


# Function to grab the banner from an open port
def grab_banner(ip, port):
    try:
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_obj.settimeout(1)
        socket_obj.connect((ip, port))

        # Send a simple request to receive a banner
        socket_obj.send(b'Hello\r\n')
        banner = socket_obj.recv(1024).decode().strip()
        socket_obj.close()
        return banner
    except (socket.timeout, socket.error, OSError) as e:
        logging.warning(f"Failed to grab banner for IP {ip} on port {port}: {e}")
        return None


# Function to resolve hostname for an IP address
def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        logging.info(f"No hostname found for IP {ip}")
        return "Hostname not found"


# Modified scan_ip function with retries and hostname resolution
def scan_ip(ip, ports, retries=3):
    open_ports = []
    hostname = resolve_hostname(ip)  # Get the hostname for the IP
    for port in ports:
        attempt = 0
        while attempt < retries:
            try:
                socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_obj.settimeout(0.5)
                result = socket_obj.connect_ex((ip, port))
                if result == 0:
                    banner = grab_banner(ip, port)  # Grab banner if port is open
                    open_ports.append((port, banner if banner else "No Banner"))
                    break  # Exit retry loop if port is open
                socket_obj.close()
            except (socket.timeout, socket.error, OSError) as e:
                logging.warning(f"Attempt {attempt + 1} failed for IP {ip} on port {port}: {e}")
            attempt += 1  # Increment attempt counter if failed
    if open_ports:
        log_result(ip, hostname, open_ports)
        return ip, hostname, open_ports
    return None


# Function to scan a range of IPs and send an email at the end
def scan_ip_range(start_ip, end_ip, ports, retries):
    results = []
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    ip_range = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]

    with ThreadPoolExecutor(max_workers=100) as executor:
        for result in tqdm(executor.map(lambda ip: scan_ip(ip, ports, retries), ip_range), total=len(ip_range),
                           desc="Scanning IPs"):
            if result:
                results.append(result)

    # Print results in table format and display summary
    print("\nScan Results:")
    print(tabulate(results, headers=["IP Address", "Hostname", "Open Ports"]))

    # Send email with the results
    send_email(results)

    # Display summary report
    display_summary(results)


# Function to display summary report
def display_summary(results):
    active_ips = len(results)
    total_open_ports = sum(len(ports) for _, _, ports in results)
    common_ports = {}
    for _, _, ports in results:
        for port, _ in ports:
            common_ports[port] = common_ports.get(port, 0) + 1

    most_common_ports = sorted(common_ports.items(), key=lambda x: x[1], reverse=True)[:5]

    print("\n--- Scan Summary ---")
    print(f"Total active IPs: {active_ips}")
    print(f"Total open ports found: {total_open_ports}")
    print("Most common open ports:")
    for port, count in most_common_ports:
        print(f"Port {port}: {count} times")


# Function to send an email with scan results
def send_email(results):
    # Replace with your actual email and password
    sender_email = "kkwc2ke@gmail.com"
    receiver_email = "randolphseanj@gmail.com"
    password = "tdwo pvdi ijjo qstv"

    # Set up the email message
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = "IP Scan Results"

    # Format the results for the email body
    body = "IP Scan Results:\n\n"
    for ip, hostname, open_ports in results:
        ports_info = ", ".join([f"Port {port} ({banner})" for port, banner in open_ports])
        body += f"{ip} ({hostname}): {ports_info}\n"

    msg.attach(MIMEText(body, "plain"))

    # Send the email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:  # Replace with your SMTP server
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Email sent successfully!")
    except (smtplib.SMTPException, ConnectionRefusedError, TimeoutError) as e:
        logging.error(f"Failed to send email: {e}")


# Command-line argument parsing
def main():
    parser = argparse.ArgumentParser(description="IP Scanner Tool")
    parser.add_argument("--start-ip", required=True, help="Start IP address")
    parser.add_argument("--end-ip", required=True, help="End IP address")
    parser.add_argument("--ports", required=True, nargs="+", type=int, help="List of ports to scan")
    parser.add_argument("--retries", type=int, default=3, help="Number of retry attempts for each port")
    args = parser.parse_args()

    # Validate IP addresses
    if not (validate_ip(args.start_ip) and validate_ip(args.end_ip)):
        print("Invalid IP range. Exiting...")
        return

    # Start scanning
    print(
        f"Starting scan from {args.start_ip} to {args.end_ip} on ports {args.ports} with {args.retries} retries per port")
    scan_ip_range(args.start_ip, args.end_ip, args.ports, args.retries)


if __name__ == "__main__":
    main()
