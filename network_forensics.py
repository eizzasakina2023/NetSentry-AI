import os
import pyshark
from datetime import datetime
from termcolor import colored
from transformers import pipeline
from pyshark.capture.capture import TSharkCrashException
print(f"hi guyss")
# Load Hugging Face model (Use a smaller model for faster performance)
classifier = pipeline('zero-shot-classification', model='facebook/bart-large-mnli')

# Attack types for classification
attack_labels = ["SQL Injection", "XSS", "DDoS"]

# Detect attacks (with batching for efficiency)
def detect_attacks(details_batch):
    predictions = classifier(details_batch, candidate_labels=attack_labels)
    return [prediction['labels'][0] for prediction in predictions]  # Most likely attack type

# Analyze PCAP file with optimizations and error handling
def analyze_pcap(file_path, max_packets=1000, batch_size=10):
    report = []
    details_batch = []
    try:
        pcap = pyshark.FileCapture(
            file_path,
            display_filter='http or dns',  # Simplified filter
            keep_packets=False,
            use_json=True  # Use JSON for faster processing
        )
        pcap.set_debug()  # Enable debug mode

        for i, packet in enumerate(pcap):
            if i >= max_packets:  # Limit packets to avoid overheating
                break
            try:
                source = packet.ip.src if 'IP' in packet else 'Unknown'
                destination = packet.ip.dst if 'IP' in packet else 'Unknown'
                timestamp = packet.sniff_time.isoformat()
                protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'
                details = packet.http.file_data if "HTTP" in packet else str(packet.highest_layer)

                # Add packet details to batch for attack detection
                details_batch.append(details)
                
                if len(details_batch) >= batch_size:
                    # Perform attack detection
                    attack_types = detect_attacks(details_batch)
                    for j, attack_type in enumerate(attack_types):
                        report.append({
                            "type": attack_type,
                            "source": source,
                            "destination": destination,
                            "protocol": protocol,
                            "timing": timestamp,
                            "details": details_batch[j]
                        })
                    details_batch = []  # Reset batch
            except AttributeError:
                continue

        # Process remaining packets in the batch
        if details_batch:
            attack_types = detect_attacks(details_batch)
            for j, attack_type in enumerate(attack_types):
                # Ensure that source, destination, protocol, and timing are filled correctly
                report.append({
                    "type": attack_type,
                    "source": source if source != 'Unknown' else 'Unknown',
                    "destination": destination if destination != 'Unknown' else 'Unknown',
                    "protocol": protocol if protocol != 'Unknown' else 'Unknown',
                    "timing": timestamp if timestamp != 'Unknown' else 'Unknown',
                    "details": details_batch[j]
                })
        pcap.close()
    except TSharkCrashException as e:
        print(colored(f"TShark crashed: {e}. Please check your installation.", "red"))
    except Exception as e:
        print(colored(f"Unexpected error during analysis: {e}", "red"))
    finally:
        try:
            pcap.close()
        except:
            pass  # Ensure cleanup even if an error occurs
    return report

# Generate report
def generate_report(file_path, report_data):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_output = os.path.join(os.path.dirname(file_path), f"report_{timestamp}.txt")

    with open(report_output, 'w') as report_file:
        report_file.write(f"Report for {file_path}\n")
        report_file.write(f"Generated on: {datetime.now()}\n")
        report_file.write("="*50 + "\n")

        for entry in report_data:
            report_file.write(f"Attack Type: {entry['type']}\n")
            report_file.write(f"Source: {entry['source']}\n")
            report_file.write(f"Destination: {entry['destination']}\n")
            report_file.write(f"Protocol: {entry['protocol']}\n")
            report_file.write(f"Timing: {entry['timing']}\n")
            report_file.write(f"Details: {entry['details']}\n")
            report_file.write("-"*50 + "\n")

    print(colored(f"Report saved to {report_output}", "green"))

# Main function
def main():
    print(colored("Network Forensics Tool", "cyan", attrs=["bold"]))
    file_path = input(colored("Enter the PCAP file path: ", "yellow")).strip()

    if not os.path.isfile(file_path) or not file_path.endswith('.pcap'):
        print(colored("Invalid file path or unsupported file type.", "red"))
        return

    print(colored("Analyzing PCAP file...", "blue"))
    report_data = analyze_pcap(file_path, max_packets=1000, batch_size=10)  # Adjust max_packets as needed
    if report_data:
        generate_report(file_path, report_data)
        print(colored("Analysis completed!", "green", attrs=["bold"]))
    else:
        print(colored("No data was processed from the PCAP file.", "red"))

if __name__ == "__main__":
    main()
