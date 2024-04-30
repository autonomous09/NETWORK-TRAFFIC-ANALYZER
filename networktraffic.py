from scapy.layers.inet import IP, TCP, UDP, ICMP, Ether
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
from scapy.all import *


class NetworkAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("800x600")

        self.create_widgets()
        self.is_sniffing = False
        self.packets = []

    def create_widgets(self):
        # Frame for packet display
        packet_frame = ttk.LabelFrame(self.root, text="Captured Packets")
        packet_frame.pack(pady=10, fill="both", expand=True)

        # Text area to display packets
        self.packet_display = scrolledtext.ScrolledText(packet_frame, width=100, height=20)
        self.packet_display.pack(pady=10, fill="both", expand=True)
        self.packet_display.bind("<Double-Button-1>", self.show_packet_details)

        # Frame for controls
        control_frame = ttk.LabelFrame(self.root, text="Controls")
        control_frame.pack(pady=10, fill="both")

        # Button to start/stop packet sniffing
        self.sniff_button = ttk.Button(control_frame, text="Start Sniffing", command=self.toggle_sniffing)
        self.sniff_button.pack(side="left", padx=10, pady=5)

        # Button to save captured packets
        save_button = ttk.Button(control_frame, text="Save Packets", command=self.save_packets_to_file)
        save_button.pack(side="left", padx=10, pady=5)

        # Button to clear displayed packets
        clear_button = ttk.Button(control_frame, text="Clear Packets", command=self.clear_packets)
        clear_button.pack(side="left", padx=10, pady=5)

        # Button to plot packet protocols
        plot_button = ttk.Button(control_frame, text="Plot Protocols", command=self.plot_protocols)
        plot_button.pack(side="left", padx=10, pady=5)

        # Button to analyze packets
        analyze_button = ttk.Button(control_frame, text="Analyze Packets", command=self.analyze_packets)
        analyze_button.pack(side="left", padx=10, pady=5)

        # Create a text widget for displaying packet details
        self.packet_details_text = tk.Text(self.root, wrap="word", height=20, width=100)
        self.packet_details_text.pack(pady=10, fill="both", expand=True)

    def toggle_sniffing(self):
        if not self.is_sniffing:
            self.start_sniffing()
            self.sniff_button.config(text="Stop Sniffing")
        else:
            self.stop_sniffing()
            self.sniff_button.config(text="Start Sniffing")

    def start_sniffing(self):
        iface = "Wi-Fi"  # Set your Wi-Fi interface name here
        num_packets = 0  # Capture indefinitely

        self.is_sniffing = True

        def sniff_packets():
            nonlocal num_packets
            while self.is_sniffing:
                try:
                    packet = sniff(iface=iface, filter="tcp or udp or icmp", count=1)
                    self.display_packets(packet)
                    self.packets.append(packet[0])  # Store only the first packet for display
                    num_packets += 1
                except Exception as e:
                    print(f"Error while sniffing packets: {str(e)}")

        # Start packet sniffing in a separate thread
        threading.Thread(target=sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.is_sniffing = False

    def display_packets(self, packet):
        packet_summary = str(packet.summary())
        self.packet_display.insert("end", packet_summary + "\n", packet_summary)

    def show_packet_details(self, event):
        index = self.packet_display.index(tk.CURRENT)
        packet = self.packets[int(index.split(".")[0]) - 1]  # Get the clicked packet
        packet_details = str(packet.show(dump=True))
        self.packet_details_text.delete("1.0", "end")
        self.packet_details_text.insert("1.0", packet_details)

    def clear_packets(self):
        self.packet_display.delete("1.0", "end")
        self.packets = []

    def plot_protocols(self):
        if not self.packets:
            messagebox.showinfo("Info", "No packets to plot.")
            return

        protocols = self.extract_protocols(self.packets)
        self.show_protocol_plot(protocols)

    def extract_protocols(self, packets):
        protocols = Counter()
        for packet in packets:
            if IP in packet:
                protocol = "IPv4" if packet.haslayer(IP) else "IPv6"
            elif Ether in packet:
                protocol = "Ethernet"
            elif TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = "Other"

            protocols[protocol] += 1

        return protocols

    def show_protocol_plot(self, protocols):
        labels = protocols.keys()
        values = protocols.values()

        fig, ax = plt.subplots()
        ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, shadow=True, explode=[0.1]*len(labels))
        ax.axis('equal')

        plt.title("Packet Protocols Distribution")

        # Create a new Toplevel window for the plot
        plot_window = tk.Toplevel(self.root)
        plot_window.title("Protocol Distribution")
        plot_window.geometry("600x400")

        # Embed plot in tkinter window
        canvas = FigureCanvasTkAgg(fig, master=plot_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def save_packets_to_file(self):
        if not self.packets:
            messagebox.showinfo("Info", "No packets to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".pcap")
        if file_path:
            wrpcap(file_path, self.packets)
            messagebox.showinfo("Success", f"Packets saved to {file_path}.")

    def analyze_packets(self):
        if not self.packets:
            messagebox.showinfo("Info", "No packets to analyze.")
            return

        num_packets = len(self.packets)
        protocols = self.extract_protocols(self.packets)
        traffic_volume = sum(len(packet) for packet in self.packets)

        analysis_info = (
            f"Packet Analysis\n\n"
            f"Number of Packets: {num_packets}\n"
            f"Traffic Volume: {traffic_volume} bytes\n\n"
            f"Protocol Counts:\n"
        )

        for protocol, count in protocols.items():
            analysis_info += f"    - {protocol}: {count}\n"

        messagebox.showinfo("Packet Analysis", analysis_info)


def main():
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
