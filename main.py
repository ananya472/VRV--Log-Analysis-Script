import re
from collections import Counter, defaultdict
import csv

# Function to parse the log file
def parse_log_file(file_path):
    logs = []
    with open(file_path, 'r') as file:
        for line in file:
            logs.append(line.strip())
    return logs

# Function to count requests per IP address and track endpoints
def count_requests_and_endpoints_per_ip(logs):
    ip_pattern = r'^(\d+\.\d+\.\d+\.\d+)'
    endpoint_pattern = r'\"(?:GET|POST) (.+?) HTTP'
    failed_login_pattern = r'^(\d+\.\d+\.\d+\.\d+).+\"POST /login HTTP.+401'

    ip_counts = defaultdict(int)
    endpoint_counts = Counter()
    failed_login_counts = defaultdict(int)

    for log in logs:
        ip_match = re.match(ip_pattern, log)
        endpoint_match = re.search(endpoint_pattern, log)
        failed_login_match = re.match(failed_login_pattern, log)

        # Count requests per IP
        if ip_match:
            ip = ip_match.group(1)
            ip_counts[ip] += 1
            
            # Track accessed endpoints
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1

            # Count failed login attempts for each IP
            if failed_login_match:
                failed_login_ip = failed_login_match.group(1)
                failed_login_counts[failed_login_ip] += 1

    return ip_counts, endpoint_counts, failed_login_counts

# Function to save results to a CSV file
def save_to_csv(ip_counts, endpoint_counts, failed_login_counts, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])

        # Most accessed endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        most_common_endpoint, access_count = endpoint_counts.most_common(1)[0]
        writer.writerow([most_common_endpoint, access_count])
        writer.writerow([])

        # Failed login counts per IP
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_login_counts.items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file = r'C:\Users\anany\Desktop\vrv\sample.log'  # Log file path
    output_file = 'log_analysis_results.csv'
    
    logs = parse_log_file(log_file)
    
    # 1. Count requests per IP address and track endpoint access
    ip_counts, endpoint_counts, failed_login_counts = count_requests_and_endpoints_per_ip(logs)
    
    # 2. Display the counts for each IP address
    print("IP Address Request Counts:")
    for ip, count in ip_counts.items():
        print(f"{ip} - {count}")
    print("\n")

    # 3. Display the most frequently accessed endpoint
    most_common_endpoint, endpoint_count = endpoint_counts.most_common(1)[0]
    print(f"Most Frequently Accessed Endpoint:\n{most_common_endpoint} (Accessed {endpoint_count} times)")
    print("\n")

    # 4. Display failed login counts per IP
    print("Failed Login Counts Per IP:")
    for ip, count in failed_login_counts.items():
        print(f"{ip} - {count} failed attempts")
    print("\n")

    # Save results to CSV
    save_to_csv(ip_counts, endpoint_counts, failed_login_counts, output_file)
    print(f"Results saved to {output_file}")

# Run the script
if __name__ == '__main__':
    main()

