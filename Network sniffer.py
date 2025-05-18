from scapy.all import *
from collections import defaultdict
import matplotlib.pyplot as plt
import platform
import time

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_counts = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.destination_ips = defaultdict(int)
        self.start_time = time.time()
        self.packet_sizes = []
        self.timestamps = []
        
    def packet_handler(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        current_time = time.time() - self.start_time
        self.timestamps.append(current_time)
        
        # Record packet size
        if hasattr(packet, 'len'):
            self.packet_sizes.append(packet.len)
        
        # IP layer analysis
        if IP in packet:
            ip_layer = packet[IP]
            self.source_ips[ip_layer.src] += 1
            self.destination_ips[ip_layer.dst] += 1
            
            # Protocol analysis
            if TCP in packet:
                self.protocol_counts["TCP"] += 1
            elif UDP in packet:
                self.protocol_counts["UDP"] += 1
            elif ICMP in packet:
                self.protocol_counts["ICMP"] += 1
            else:
                self.protocol_counts["Other"] += 1
                
        # Display basic packet info
        print(f"\nPacket #{self.packet_count}")
        print(packet.summary())
        
        # For more detailed analysis, uncomment:
        # print(packet.show())
        
    def start_sniffing(self, interface=None, count=100, filter=None):
        """Start capturing packets"""
        print(f"Starting packet capture on interface {interface or 'default'}...")
        print("Press Ctrl+C to stop and view statistics.")
        
        try:
            sniff(
                prn=self.packet_handler,
                iface=interface,
                count=count,
                filter=filter,
                store=False
            )
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
        finally:
            self.display_statistics()
            
    def display_statistics(self):
        """Display captured traffic statistics"""
        print("\n=== Network Traffic Statistics ===")
        print(f"Total packets captured: {self.packet_count}")
        print(f"Capture duration: {time.time() - self.start_time:.2f} seconds")
        
        print("\nProtocol Distribution:")
        for proto, count in self.protocol_counts.items():
            print(f"{proto}: {count} packets ({count/self.packet_count:.1%})")
            
        print("\nTop 5 Source IPs:")
        for ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{ip}: {count} packets")
            
        print("\nTop 5 Destination IPs:")
        for ip, count in sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{ip}: {count} packets")
            
        # Plot traffic over time
        if self.packet_sizes:
            self.plot_traffic()
            
    def plot_traffic(self):
        """Plot packet sizes over time"""
        plt.figure(figsize=(12, 6))
        
        # Packet size over time
        plt.subplot(1, 2, 1)
        plt.plot(self.timestamps, self.packet_sizes, 'b.')
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packet Size (bytes)')
        plt.title('Packet Sizes Over Time')
        
        # Protocol distribution
        plt.subplot(1, 2, 2)
        if self.protocol_counts:
            labels = self.protocol_counts.keys()
            sizes = self.protocol_counts.values()
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=True)
            plt.title('Protocol Distribution')
        
        plt.tight_layout()
        plt.show()

def get_default_interface():
    """Get the default network interface"""
    if platform.system() == "Linux":
        return conf.iface
    elif platform.system() == "Windows":
        return conf.iface.device_name
    else:  # macOS
        return conf.iface

if __name__ == "__main__":
    sniffer = NetworkSniffer()
    
    # Get available interfaces
    print("Available interfaces:")
    print(ifaces)
    
    # Start sniffing
    interface = input("Enter interface to sniff (leave blank for default): ").strip() or None
    packet_count = int(input("Enter number of packets to capture (0 for unlimited): ") or "100")
    filter_expr = input("Enter BPF filter (e.g., 'tcp port 80' or leave blank): ").strip() or None
    
    try:
        if packet_count == 0:
            packet_count = None  # Capture until interrupted
            
        sniffer.start_sniffing(
            interface=interface,
            count=packet_count,
            filter=filter_expr
        )
    except PermissionError:
        print("Error: Permission denied. Try running with sudo/administrator privileges.")
    except Exception as e:
        print(f"Error: {e}")
