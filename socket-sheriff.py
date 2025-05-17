"""
Socket Sheriff

A PyQt5-based application for monitoring network connections and capturing packets on Windows.
Displays active network connections with process information and allows packet sniffing 
for selected processes by filtering based on the ports that process is using.

Required dependencies:
- PyQt5: GUI framework
- psutil: Process and system information
- scapy: Packet capture and analysis
- Pillow: Image processing for icons

License: MIT
"""

import sys
import os
import datetime
import time
import csv
import subprocess
import io
import threading
import ctypes
from ctypes import byref, c_char, sizeof, memset, create_string_buffer
from ctypes import c_int, c_void_p, POINTER
from ctypes.wintypes import *
from PIL import Image
import psutil
import socket
from collections import defaultdict
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, rdpcap

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QPushButton, QLabel, 
                           QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
                           QSplitter, QTabWidget, QHeaderView, QMenu, QAction, 
                           QFileDialog, QMessageBox, QTextEdit, QScrollArea, QAbstractItemView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt5.QtGui import QIcon, QPixmap, QImage, QColor, QPalette, QFont


#-------------------------------------------------------------------------------
# Windows API Interface for Icon Extraction
#-------------------------------------------------------------------------------

# Constants for icon extraction
BI_RGB = 0
DIB_RGB_COLORS = 0

class ICONINFO(ctypes.Structure):
    """Windows ICONINFO structure for icon handling"""
    _fields_ = [
        ("fIcon", BOOL),
        ("xHotspot", DWORD),
        ("yHotspot", DWORD),
        ("hbmMask", HBITMAP),
        ("hbmColor", HBITMAP)
    ]

class RGBQUAD(ctypes.Structure):
    """Windows RGBQUAD structure for color representation"""
    _fields_ = [
        ("rgbBlue", BYTE),
        ("rgbGreen", BYTE),
        ("rgbRed", BYTE),
        ("rgbReserved", BYTE),
    ]

class BITMAPINFOHEADER(ctypes.Structure):
    """Windows BITMAPINFOHEADER structure for bitmap info"""
    _fields_ = [
        ("biSize", DWORD),
        ("biWidth", LONG),
        ("biHeight", LONG),
        ("biPlanes", WORD),
        ("biBitCount", WORD),
        ("biCompression", DWORD),
        ("biSizeImage", DWORD),
        ("biXPelsPerMeter", LONG),
        ("biYPelsPerMeter", LONG),
        ("biClrUsed", DWORD),
        ("biClrImportant", DWORD)
    ]

class BITMAPINFO(ctypes.Structure):
    """Windows BITMAPINFO structure combining header and color palette"""
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", RGBQUAD * 1),
    ]

# Load Windows DLLs
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

# Setup function prototypes
gdi32.CreateCompatibleDC.argtypes = [HDC]
gdi32.CreateCompatibleDC.restype = HDC
gdi32.GetDIBits.argtypes = [HDC, HBITMAP, UINT, UINT, LPVOID, c_void_p, UINT]
gdi32.GetDIBits.restype = c_int
gdi32.DeleteObject.argtypes = [HGDIOBJ]
gdi32.DeleteObject.restype = BOOL
shell32.ExtractIconExW.argtypes = [LPCWSTR, c_int, POINTER(HICON), POINTER(HICON), UINT]
shell32.ExtractIconExW.restype = UINT
user32.GetIconInfo.argtypes = [HICON, POINTER(ICONINFO)]
user32.GetIconInfo.restype = BOOL
user32.DestroyIcon.argtypes = [HICON]
user32.DestroyIcon.restype = BOOL


#-------------------------------------------------------------------------------
# Worker Threads
#-------------------------------------------------------------------------------

class SnifferThread(QThread):
    """Thread for packet sniffing"""
    packet_captured = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    status_update = pyqtSignal(str)
    
    def __init__(self, pid, ports):
        """Initialize the sniffer thread
        
        Args:
            pid: Process ID to monitor
            ports: List of ports to monitor
        """
        super().__init__()
        self.pid = pid
        self.ports = ports
        self.is_running = False
        self.stop_requested = False
        self.packet_count = 0
        self._debug = False  # Set to True for debug logging
    
    def debug_log(self, msg):
        """Log debug messages if debug is enabled
        
        Args:
            msg: Message to log
        """
        if self._debug:
            self.status_update.emit(f"DEBUG: {msg}")
    
    def run(self):
        """Main thread execution loop for packet capture"""
        self.is_running = True
        self.stop_requested = False
        self.packet_count = 0
        
        self.debug_log("Sniffer thread starting")
        
        try:
            # Check if we have ports to listen on
            if not self.ports:
                self.error_occurred.emit("No active ports found for this process. Watching all traffic instead.")
                
            # Create filter expression - if no ports, don't use a filter
            if self.ports:
                filter_expr = f"port {' or port '.join(map(str, self.ports))}"
                self.status_update.emit(f"Starting capture with filter: {filter_expr}")
            else:
                filter_expr = ""  # No filter
                self.status_update.emit("Starting capture with no filter (watching all traffic)")
            
            # Main capture loop - runs until stop_requested is set
            while not self.stop_requested:
                try:
                    # Capture a batch of packets with a short timeout
                    # This ensures we can check the stop condition frequently
                    packets = sniff(
                        filter=filter_expr,
                        count=10,  # Process in small batches
                        timeout=1,  # Short timeout
                        store=True  # Need to store to process them
                    )
                    
                    # Process any captured packets
                    if packets:
                        self.debug_log(f"Captured {len(packets)} packets in batch")
                        for packet in packets:
                            if self.stop_requested:
                                break
                            self.process_packet(packet)
                    
                except Exception as inner_e:
                    self.error_occurred.emit(f"Capture error: {str(inner_e)}")
                    time.sleep(0.1)  # Avoid tight loop on repeated errors
                    
                # Check if we should stop
                if self.stop_requested:
                    self.debug_log("Stop requested inside main loop")
                    break
            
            self.status_update.emit(f"Sniffing stopped. Processed {self.packet_count} packets.")
            
        except Exception as e:
            self.error_occurred.emit(f"Fatal error in sniffing thread: {str(e)}")
        finally:
            self.is_running = False
            self.debug_log("Sniffer thread exiting")
    
    def stop(self):
        """Request the sniffer to stop"""
        self.debug_log("Stop requested")
        self.stop_requested = True
    
    def process_packet(self, packet):
        """Process a single captured packet
        
        Args:
            packet: The captured packet to process
        """
        try:
            # Skip processing if we've been asked to stop
            if self.stop_requested:
                return
            
            # Get current time
            now = datetime.datetime.now()
            time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            
            # Extract basic info
            src = ""
            dst = ""
            proto = ""
            length = len(packet)
            
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                proto = "IP"
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                src = f"{src}:{src_port}" if src else f"?:{src_port}"
                dst = f"{dst}:{dst_port}" if dst else f"?:{dst_port}"
                proto = "TCP"
                
                # Check for HTTP/HTTPS
                if dst_port == 80 or src_port == 80:
                    proto = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    proto = "HTTPS/TLS"
            
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                src = f"{src}:{src_port}" if src else f"?:{src_port}"
                dst = f"{dst}:{dst_port}" if dst else f"?:{dst_port}"
                proto = "UDP"
            
            # Check if packet is related to our process by matching ports
            # If no ports specified, accept all packets
            related = True
            
            if self.ports:  # Only filter if we have specific ports
                related = False
                if TCP in packet or UDP in packet:
                    sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
                    dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
                    if sport in self.ports or dport in self.ports:
                        related = True
            
            if related:
                # Increment packet count
                self.packet_count += 1
                
                # Create and emit the packet data
                packet_data = {
                    "time": time_str,
                    "source": src,
                    "destination": dst,
                    "protocol": proto,
                    "length": length,
                    "raw": bytes(packet)
                }
                
                # Emit the signal if we're still running
                if not self.stop_requested:
                    self.packet_captured.emit(packet_data)
                
                # Emit a status update every 10 packets
                if self.packet_count % 10 == 0:
                    self.status_update.emit(f"Captured {self.packet_count} packets")
                    
        except Exception as e:
            self.error_occurred.emit(f"Error processing packet: {str(e)}")
            # Continue processing other packets


class MonitoringThread(QThread):
    """Thread for monitoring network connections"""
    update_required = pyqtSignal()
    
    def __init__(self):
        """Initialize the monitoring thread"""
        super().__init__()
        self.is_running = False
        self.connections = defaultdict(list)
        self.process_info = {}
        
    def run(self):
        """Main thread execution loop for monitoring network connections"""
        self.is_running = True
        
        while self.is_running:
            try:
                # Get all connections
                connections = psutil.net_connections(kind='inet')
                
                # Current timestamp
                now = datetime.datetime.now()
                time_str = now.strftime("%Y-%m-%d %H:%M:%S")
                
                # Keep track of active PIDs
                active_pids = set()
                
                # Process each connection
                for conn in connections:
                    if conn.pid is None:
                        continue
                    
                    pid = conn.pid
                    active_pids.add(pid)
                    
                    # Create connection record
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn, 'laddr') and conn.laddr else "N/A"
                    
                    # For remote addresses, handle empty/listening sockets
                    if hasattr(conn, 'raddr') and conn.raddr:
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                    else:
                        # For listening sockets
                        if conn.status == "LISTEN":
                            remote_addr = "*:*"
                        else:
                            remote_addr = "N/A"
                    
                    protocol = conn.type
                    
                    if protocol == socket.SOCK_STREAM:
                        protocol_str = "TCP"
                    elif protocol == socket.SOCK_DGRAM:
                        protocol_str = "UDP"
                    else:
                        protocol_str = str(protocol)
                    
                    # Add status to protocol if it's a listening socket
                    if conn.status == "LISTEN":
                        protocol_str += " (LISTEN)"
                    
                    # Always update process info for any network connection
                    if pid not in self.process_info:
                        try:
                            proc = psutil.Process(pid)
                            name = proc.name()
                            try:
                                ppid = proc.ppid()
                                parent = psutil.Process(ppid)
                                parent_name = parent.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                ppid = 0
                                parent_name = "Unknown"
                            
                            # Get process icon
                            icon = self.extract_icon(proc.exe())
                            
                            self.process_info[pid] = {
                                "name": name,
                                "ppid": ppid,
                                "parent_name": parent_name,
                                "first_seen": time_str,
                                "last_seen": "",  # Only set when terminated
                                "icon": icon,
                                "status": "Active"
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    else:
                        # Only update status to Active, don't update last_seen
                        self.process_info[pid]["status"] = "Active"
                    
                    # Check if this connection is already recorded
                    connection_record = {
                        "local": local_addr,
                        "remote": remote_addr,
                        "protocol": protocol_str,
                        "time": time_str
                    }
                    
                    # Add to connections only if it's a new connection
                    is_new = True
                    for existing_conn in self.connections[pid]:
                        if (existing_conn["local"] == local_addr and 
                            existing_conn["remote"] == remote_addr and
                            existing_conn["protocol"] == protocol_str):
                            is_new = False
                            break
                    
                    if is_new:
                        self.connections[pid].append(connection_record)
                
                # Check for ICMP traffic (like ping)
                self.check_icmp_traffic(active_pids, time_str)
                
                # Mark terminated processes
                for pid in list(self.process_info.keys()):
                    if pid not in active_pids and self.process_info[pid]["status"] == "Active":
                        self.process_info[pid]["status"] = "Terminated"
                        # Only set last_seen when process terminates
                        self.process_info[pid]["last_seen"] = time_str
                
                # Signal the main thread that an update is needed
                self.update_required.emit()
                
                # Sleep for a short interval
                time.sleep(1)
                
            except Exception as e:
                print(f"Error in monitoring: {e}")
                time.sleep(2)  # In case of error, wait a bit longer
    
    def stop(self):
        """Request the monitoring thread to stop"""
        self.is_running = False
    
    def is_icmp_process(self, pid):
        """Check if this process is likely using ICMP (ping)
        
        Args:
            pid: Process ID to check
            
        Returns:
            bool: True if the process is likely using ICMP
        """
        try:
            proc = psutil.Process(pid)
            if proc.name().lower() in ["ping.exe", "cmd.exe", "powershell.exe"]:
                return True
                
            # For more comprehensive detection, check command line args
            try:
                cmdline = proc.cmdline()
                if any("ping" in arg.lower() for arg in cmdline):
                    return True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return False
    
    def check_icmp_traffic(self, active_pids, time_str):
        """Check for ICMP traffic using heuristics
        
        Args:
            active_pids: Set of currently active process IDs
            time_str: Current timestamp string
        """
        try:
            # Look for ping processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'].lower()
                    cmdline = proc.info['cmdline']
                    
                    # Skip if we already know this process
                    if pid in self.process_info and self.process_info[pid]["status"] == "Active":
                        continue
                        
                    # Check if it's likely a ping process
                    is_ping = False
                    ping_target = None
                    
                    if name == "ping.exe":
                        is_ping = True
                        # Extract target from cmdline if available
                        if cmdline and len(cmdline) > 1:
                            for arg in cmdline[1:]:
                                if not arg.startswith("-"):
                                    ping_target = arg
                                    break
                    
                    elif (name in ["cmd.exe", "powershell.exe"] and 
                          cmdline and any("ping" in arg.lower() for arg in cmdline)):
                        is_ping = True
                        # Try to extract target from command line
                        ping_index = -1
                        for i, arg in enumerate(cmdline):
                            if "ping" in arg.lower():
                                ping_index = i
                                break
                                
                        if ping_index >= 0 and ping_index + 1 < len(cmdline):
                            possible_target = cmdline[ping_index + 1]
                            if not possible_target.startswith("-"):
                                ping_target = possible_target
                    
                    if is_ping:
                        active_pids.add(pid)
                        
                        # Add to process info if not already there
                        if pid not in self.process_info:
                            try:
                                ppid = proc.ppid()
                                parent = psutil.Process(ppid)
                                parent_name = parent.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                ppid = 0
                                parent_name = "Unknown"
                            
                            # Get process icon
                            icon = self.extract_icon(proc.exe())
                            
                            self.process_info[pid] = {
                                "name": name,
                                "ppid": ppid,
                                "parent_name": parent_name,
                                "first_seen": time_str,
                                "last_seen": "",
                                "icon": icon,
                                "status": "Active"
                            }
                        else:
                            self.process_info[pid]["status"] = "Active"
                        
                        # Add ICMP connection if target identified
                        if ping_target:
                            # Create a fake connection record for ICMP
                            connection_record = {
                                "local": "ICMP",
                                "remote": ping_target,
                                "protocol": "ICMP",
                                "time": time_str
                            }
                            
                            # Check if we already have this connection
                            is_new = True
                            for existing_conn in self.connections[pid]:
                                if (existing_conn["remote"] == ping_target and
                                    existing_conn["protocol"] == "ICMP"):
                                    is_new = False
                                    break
                            
                            if is_new:
                                self.connections[pid].append(connection_record)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"Error checking ICMP: {e}")
    
    def extract_icon(self, filename):
        """Extract icon from a file and convert to QIcon
        
        Args:
            filename: Path to the executable file
            
        Returns:
            QIcon: The icon extracted from the file, or None if not found
        """
        try:
            if not filename or not os.path.exists(filename):
                return None
                
            # Create a device context
            dc = gdi32.CreateCompatibleDC(0)
            if dc == 0:
                return None
            
            # Extract icon
            hicon = HICON()
            icon_index = 0
            
            # Extract small icon for better display in table
            extracted = shell32.ExtractIconExW(
                filename, icon_index, None, byref(hicon), 1
            )
            
            if extracted != 1:
                return None
                
            # Get icon info
            icon_info = ICONINFO()
            if not user32.GetIconInfo(hicon, byref(icon_info)):
                if hicon:
                    user32.DestroyIcon(hicon)
                return None
                
            # Setup bitmap info
            bmi = BITMAPINFO()
            memset(byref(bmi), 0, sizeof(bmi))
            bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER)
            bmi.bmiHeader.biWidth = 16  # Small icon
            bmi.bmiHeader.biHeight = -16  # Negative for top-down
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = BI_RGB
            bmi.bmiHeader.biSizeImage = 16 * 16 * 4
            
            # Get bitmap data
            bits = create_string_buffer(bmi.bmiHeader.biSizeImage)
            result = gdi32.GetDIBits(
                dc, icon_info.hbmColor, 0, 16, bits, byref(bmi), DIB_RGB_COLORS
            )
            
            # Clean up resources
            if icon_info.hbmColor:
                gdi32.DeleteObject(icon_info.hbmColor)
            if icon_info.hbmMask:
                gdi32.DeleteObject(icon_info.hbmMask)
            if hicon:
                user32.DestroyIcon(hicon)
            
            # Return the icon data converted to QIcon
            if result > 0:
                # Convert bitmap data to QImage
                img = QImage(
                    bits.raw, 16, 16, 16 * 4, QImage.Format_ARGB32
                )
                # Convert to QPixmap and then to QIcon
                pixmap = QPixmap.fromImage(img)
                return QIcon(pixmap)
            
            return None
                
        except Exception as e:
            print(f"Error extracting icon: {e}")
            return None


#-------------------------------------------------------------------------------
# Main Application Window
#-------------------------------------------------------------------------------

class NetworkMonitor(QMainWindow):
    """Main application window for network monitoring"""
    
    def __init__(self):
        """Initialize the main window"""
        super().__init__()
        
        # Window properties
        self.setWindowTitle("Socket Sheriff")
        self.setGeometry(100, 100, 1200, 700)
        
        # Set dark theme colors
        self.setup_dark_theme()
        
        # Initialize member variables
        self.selected_pid = None
        self.sniffing = False
        self.sniffer_thread = None
        self.sniff_data = []
        
        # Create main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        # Main layout
        self.main_layout = QVBoxLayout(self.main_widget)
        
        # Create the UI components
        self.create_ui()
        
        # Start monitoring thread
        self.monitor_thread = MonitoringThread()
        self.monitor_thread.update_required.connect(self.update_process_list)
        self.monitor_thread.start()
    
    def setup_dark_theme(self):
        """Set up dark theme colors and styling"""
        # Define colors
        self.bg_color = "#1A1A1D"  # Very dark gray with slight blue tint
        self.accent_color = "#252529"  # Dark gray with slight blue tint
        self.selection_color = "#36363D"  # Medium gray with slight blue tint
        self.text_color = "#E0E0E0"  # Light text
        self.active_color = "#50C878"  # Green for active processes
        self.inactive_color = "#FF6B6B"  # Red for terminated processes
        
        # Set application style
        app = QApplication.instance()
        app.setStyle("Fusion")
        
        # Create dark palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(self.bg_color))
        palette.setColor(QPalette.WindowText, QColor(self.text_color))
        palette.setColor(QPalette.Base, QColor(self.accent_color))
        palette.setColor(QPalette.AlternateBase, QColor("#2D2D30"))
        palette.setColor(QPalette.ToolTipBase, QColor(self.text_color))
        palette.setColor(QPalette.ToolTipText, QColor(self.text_color))
        palette.setColor(QPalette.Text, QColor(self.text_color))
        palette.setColor(QPalette.Button, QColor(self.accent_color))
        palette.setColor(QPalette.ButtonText, QColor(self.text_color))
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(self.selection_color))
        palette.setColor(QPalette.HighlightedText, QColor(self.text_color))
        
        # Apply palette
        app.setPalette(palette)
        
        # Additional styling
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background-color: {self.bg_color}; }}
            QTableWidget {{ 
                background-color: {self.accent_color}; 
                gridline-color: {self.bg_color};
                border: none;
                color: {self.text_color};
            }}
            QTableWidget::item:selected {{ 
                background-color: {self.selection_color}; 
                color: {self.text_color};
            }}
            QHeaderView::section {{ 
                background-color: {self.accent_color}; 
                color: {self.text_color}; 
                padding: 5px;
                border: none;
            }}
            QTabWidget::pane {{ 
                border: none; 
                background-color: {self.accent_color};
            }}
            QTabBar::tab {{ 
                background-color: {self.accent_color}; 
                color: {self.text_color}; 
                padding: 8px 12px;
                border: none;
            }}
            QTabBar::tab:selected {{ 
                background-color: {self.selection_color}; 
            }}
            QPushButton {{ 
                background-color: {self.accent_color}; 
                color: {self.text_color}; 
                padding: 6px 12px;
                border: none;
            }}
            QPushButton:hover {{ 
                background-color: {self.selection_color}; 
            }}
            QSplitter::handle {{ 
                background-color: {self.bg_color}; 
            }}
            QTextEdit {{ 
                background-color: {self.accent_color}; 
                color: {self.text_color}; 
                border: none;
            }}
            QScrollBar {{ 
                background-color: {self.accent_color}; 
                border: none;
            }}
            QScrollBar::handle {{ 
                background-color: {self.selection_color}; 
                border-radius: 3px;
            }}
            QScrollBar::add-line, QScrollBar::sub-line {{ 
                background: none; 
                border: none;
            }}
            QLabel {{ 
                color: {self.text_color}; 
                font-weight: bold;
            }}
        """)
    
    def create_ui(self):
        """Create the user interface components"""
        # Create a splitter for the main panels
        self.splitter = QSplitter(Qt.Horizontal)
        self.main_layout.addWidget(self.splitter)
        
        # Left panel - Process List
        self.create_process_panel()
        
        # Right panel - Details with tabs
        self.create_details_panel()

        # 60% for process list, 40% for details
        self.splitter.setSizes([600, 400])
    
    def create_process_panel(self):
        """Create the process list panel"""
        # Process panel container
        self.process_panel = QWidget()
        self.process_layout = QVBoxLayout(self.process_panel)
        self.process_layout.setContentsMargins(10, 10, 10, 10)
        
        # Add title
        self.process_title = QLabel("Active Network Processes")
        self.process_title.setFont(QFont("Segoe UI", 12))
        self.process_layout.addWidget(self.process_title)
        
        # Create process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(8)  # Icon, Name, PID, PPID, Parent, First Seen, Last Seen, Status
        self.process_table.setHorizontalHeaderLabels(
            ["", "Name", "PID", "PPID", "Parent", "First Seen", "Last Seen", "Status"]
        )
        
        # Set selection behavior
        self.process_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.process_table.setSelectionMode(QAbstractItemView.SingleSelection)
        
        # Set column widths
        self.process_table.setColumnWidth(0, 30)  # Icon
        self.process_table.setColumnWidth(1, 150)  # Name
        self.process_table.setColumnWidth(2, 50)  # PID
        self.process_table.setColumnWidth(3, 50)  # PPID
        self.process_table.setColumnWidth(4, 75)  # Parent
        self.process_table.setColumnWidth(5, 120)  # First Seen
        self.process_table.setColumnWidth(6, 120)  # Last Seen
        self.process_table.setColumnWidth(7, 20)  # Status
        
        # Adjust header and make rows more compact
        self.process_table.verticalHeader().setVisible(False)
        self.process_table.verticalHeader().setDefaultSectionSize(24)  # Row height
        
        # Allow last column to expand
        self.process_table.horizontalHeader().setStretchLastSection(True)
        
        # Connect signals
        self.process_table.itemSelectionChanged.connect(self.on_process_select)
        self.process_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.show_process_context_menu)
        
        # Add to layout
        self.process_layout.addWidget(self.process_table)
        
        # Add to splitter
        self.splitter.addWidget(self.process_panel)
    
    def create_details_panel(self):
        """Create the details panel with tabs"""
        # Details panel container
        self.details_panel = QWidget()
        self.details_layout = QVBoxLayout(self.details_panel)
        self.details_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.create_connections_tab()
        self.create_sniffer_tab()
        
        # Add tab widget to layout
        self.details_layout.addWidget(self.tab_widget)
        
        # Add to splitter
        self.splitter.addWidget(self.details_panel)
    
    def create_connections_tab(self):
        """Create the connections tab"""
        # Connections tab
        self.connections_tab = QWidget()
        self.connections_layout = QVBoxLayout(self.connections_tab)
        
        # Title
        self.connections_title = QLabel("Connection History")
        self.connections_title.setFont(QFont("Segoe UI", 12))
        self.connections_layout.addWidget(self.connections_title)
        
        # Create frame for tree and scrollbar
        self.connections_tree_frame = QWidget()
        self.connections_tree_frame_layout = QHBoxLayout(self.connections_tree_frame)
        self.connections_tree_frame_layout.setContentsMargins(0, 0, 0, 0)
        self.connections_layout.addWidget(self.connections_tree_frame)
        
        # Connections table
        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(4)
        self.connections_table.setHorizontalHeaderLabels(
            ["Local Address", "Remote Address", "Protocol", "Time"]
        )
        
        # Set column widths
        self.connections_table.setColumnWidth(0, 200)  # Local Address
        self.connections_table.setColumnWidth(1, 200)  # Remote Address
        self.connections_table.setColumnWidth(2, 80)  # Protocol
        
        # Hide vertical header and set selection behavior
        self.connections_table.verticalHeader().setVisible(False)
        self.connections_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        
        # Make last column stretch
        self.connections_table.horizontalHeader().setStretchLastSection(True)
        
        # Context menu
        self.connections_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.connections_table.customContextMenuRequested.connect(self.show_connection_context_menu)
        
        # Add to layout
        self.connections_tree_frame_layout.addWidget(self.connections_table)
        
        # Add tab to tab widget
        self.tab_widget.addTab(self.connections_tab, "Connections")
    
    def create_sniffer_tab(self):
        """Create the packet sniffer tab"""
        # Sniffer tab
        self.sniffer_tab = QWidget()
        self.sniffer_layout = QVBoxLayout(self.sniffer_tab)
        
        # Controls panel
        self.sniffer_controls = QWidget()
        self.sniffer_controls_layout = QHBoxLayout(self.sniffer_controls)
        self.sniffer_controls_layout.setContentsMargins(0, 0, 0, 10)
        
        # Control buttons
        self.start_sniff_btn = QPushButton("Start Sniffing")
        self.start_sniff_btn.clicked.connect(self.toggle_sniffing)
        self.sniffer_controls_layout.addWidget(self.start_sniff_btn)
        
        self.clear_sniff_btn = QPushButton("Clear")
        self.clear_sniff_btn.clicked.connect(self.clear_sniff_data)
        self.sniffer_controls_layout.addWidget(self.clear_sniff_btn)
        
        self.save_raw_btn = QPushButton("Save Raw")
        self.save_raw_btn.clicked.connect(lambda: self.save_sniff_data("raw"))
        self.sniffer_controls_layout.addWidget(self.save_raw_btn)
        
        self.save_csv_btn = QPushButton("Save CSV")
        self.save_csv_btn.clicked.connect(lambda: self.save_sniff_data("csv"))
        self.sniffer_controls_layout.addWidget(self.save_csv_btn)
        
        # Add spacer to push buttons to the left
        self.sniffer_controls_layout.addStretch()
        
        # Add controls to layout
        self.sniffer_layout.addWidget(self.sniffer_controls)
        
        # Create frame for sniffer tree and scrollbar
        self.sniffer_tree_frame = QWidget()
        self.sniffer_tree_frame_layout = QHBoxLayout(self.sniffer_tree_frame)
        self.sniffer_tree_frame_layout.setContentsMargins(0, 0, 0, 0)
        self.sniffer_layout.addWidget(self.sniffer_tree_frame)
        
        # Sniffer table
        self.sniffer_table = QTableWidget()
        self.sniffer_table.setColumnCount(5)
        self.sniffer_table.setHorizontalHeaderLabels(
            ["Time", "Source", "Destination", "Protocol", "Length"]
        )
        
        # Set column widths
        self.sniffer_table.setColumnWidth(0, 150)  # Time
        self.sniffer_table.setColumnWidth(1, 150)  # Source
        self.sniffer_table.setColumnWidth(2, 150)  # Destination
        self.sniffer_table.setColumnWidth(3, 80)  # Protocol
        
        # Hide vertical header and set selection behavior
        self.sniffer_table.verticalHeader().setVisible(False)
        self.sniffer_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        
        # Make last column stretch
        self.sniffer_table.horizontalHeader().setStretchLastSection(True)
        
        # Set row selection change handler
        self.sniffer_table.itemSelectionChanged.connect(self.on_packet_select)
        
        # Add to layout
        self.sniffer_tree_frame_layout.addWidget(self.sniffer_table)
        
        # Create frame for packet text and scrollbar
        self.packet_text_frame = QWidget()
        self.packet_text_frame_layout = QHBoxLayout(self.packet_text_frame)
        self.packet_text_frame_layout.setContentsMargins(0, 10, 0, 0)
        self.sniffer_layout.addWidget(self.packet_text_frame)
        
        # Packet details text area
        self.packet_text = QTextEdit()
        self.packet_text.setReadOnly(True)
        self.packet_text.setMinimumHeight(150)
        
        # Set monospace font for packet text
        font = QFont("Consolas", 10)
        self.packet_text.setFont(font)
        
        # Add to layout
        self.packet_text_frame_layout.addWidget(self.packet_text)
        
        # Add tab to tab widget
        self.tab_widget.addTab(self.sniffer_tab, "Packet Sniffer")
    
    def update_process_list(self):
        """Update the process list with current data"""
        # Remember the selected PID
        selected_pid = self.selected_pid
        
        # Get current data from the monitoring thread
        connections = self.monitor_thread.connections
        process_info = self.monitor_thread.process_info
        
        # Clear the table
        self.process_table.setRowCount(0)
        
        # Create a list of valid processes that have connections
        valid_processes = []
        for pid, info in process_info.items():
            if pid in connections and len(connections[pid]) > 0:
                valid_processes.append((pid, info))
        
        # Sort by process name
        valid_processes.sort(key=lambda x: x[1]["name"].lower())
        
        # Add items to the table
        self.process_table.setRowCount(len(valid_processes))
        
        for row, (pid, info) in enumerate(valid_processes):
            # Set the icon (centered in cell)
            if info["icon"]:
                icon_item = QTableWidgetItem()
                icon_item.setIcon(info["icon"])
                # Center the icon
                icon_item.setTextAlignment(Qt.AlignCenter)
                self.process_table.setItem(row, 0, icon_item)
            else:
                # Empty centered item even if no icon
                icon_item = QTableWidgetItem()
                icon_item.setTextAlignment(Qt.AlignCenter)
                self.process_table.setItem(row, 0, icon_item)
            
            # Set process name
            name_item = QTableWidgetItem(info["name"])
            self.process_table.setItem(row, 1, name_item)
            
            # Set PID
            pid_item = QTableWidgetItem(str(pid))
            pid_item.setTextAlignment(Qt.AlignCenter)
            self.process_table.setItem(row, 2, pid_item)
            
            # Set PPID
            ppid_item = QTableWidgetItem(str(info["ppid"]))
            ppid_item.setTextAlignment(Qt.AlignCenter)
            self.process_table.setItem(row, 3, ppid_item)
            
            # Set parent name
            parent_item = QTableWidgetItem(info["parent_name"])
            self.process_table.setItem(row, 4, parent_item)
            
            # Set first seen
            first_seen_item = QTableWidgetItem(info["first_seen"])
            first_seen_item.setTextAlignment(Qt.AlignCenter)
            self.process_table.setItem(row, 5, first_seen_item)
            
            # Set last seen (only if terminated)
            last_seen_item = QTableWidgetItem(info["last_seen"] if info["status"] == "Terminated" else "")
            last_seen_item.setTextAlignment(Qt.AlignCenter)
            self.process_table.setItem(row, 6, last_seen_item)
            
            # Set status with color
            status_item = QTableWidgetItem(info["status"])
            status_item.setTextAlignment(Qt.AlignCenter)
            
            # Set status color
            if info["status"] == "Active":
                status_item.setForeground(QColor(self.active_color))
            else:
                status_item.setForeground(QColor(self.inactive_color))
                
            self.process_table.setItem(row, 7, status_item)
            
            # Store the PID as item data for easy retrieval
            for col in range(8):
                item = self.process_table.item(row, col)
                if item:
                    item.setData(Qt.UserRole, pid)
        
        # Re-select the previously selected PID if it still exists
        if selected_pid is not None:
            for row in range(self.process_table.rowCount()):
                pid_item = self.process_table.item(row, 2)
                if pid_item and int(pid_item.text()) == selected_pid:
                    self.process_table.selectRow(row)
                    break
    
    def update_connection_list(self, pid):
        """Update the connections list for the selected process
        
        Args:
            pid: Process ID to show connections for
        """
        # Clear the table
        self.connections_table.setRowCount(0)
        
        # Get connections for the selected PID
        if pid in self.monitor_thread.connections:
            connections = self.monitor_thread.connections[pid]
            
            # Set the number of rows
            self.connections_table.setRowCount(len(connections))
            
            # Add connections to the table
            for row, conn in enumerate(connections):
                # Local address
                local_item = QTableWidgetItem(conn["local"])
                self.connections_table.setItem(row, 0, local_item)
                
                # Remote address
                remote_item = QTableWidgetItem(conn["remote"])
                self.connections_table.setItem(row, 1, remote_item)
                
                # Protocol
                protocol_item = QTableWidgetItem(conn["protocol"])
                protocol_item.setTextAlignment(Qt.AlignCenter)
                self.connections_table.setItem(row, 2, protocol_item)
                
                # Time
                time_item = QTableWidgetItem(conn["time"])
                time_item.setTextAlignment(Qt.AlignCenter)
                self.connections_table.setItem(row, 3, time_item)
    
    def on_process_select(self):
        """Handle process selection"""
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            return
        
        # Get the PID from the selected row
        pid_item = self.process_table.item(selected_items[0].row(), 2)
        if not pid_item:
            return
        
        pid = int(pid_item.text())
        self.selected_pid = pid
        
        # Update connections view
        self.update_connection_list(pid)
        
        # Update tab titles
        process_name = self.process_table.item(selected_items[0].row(), 1).text()
        self.tab_widget.setTabText(0, f"Connections - {process_name}")
        self.tab_widget.setTabText(1, f"Packet Sniffer - {process_name}")
        
    
    def show_process_context_menu(self, position):
        """Show context menu for process table
        
        Args:
            position: Mouse position for menu display
        """
        menu = QMenu(self)
        
        # Get selected item
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            return
        
        # Get the row
        row = selected_items[0].row()
        
        # Add menu items
        copy_name_action = QAction("Copy Process Name", self)
        copy_name_action.triggered.connect(lambda: self.copy_process_info("name"))
        menu.addAction(copy_name_action)
        
        copy_pid_action = QAction("Copy PID", self)
        copy_pid_action.triggered.connect(lambda: self.copy_process_info("pid"))
        menu.addAction(copy_pid_action)
        
        open_location_action = QAction("Open Process Location", self)
        open_location_action.triggered.connect(self.open_process_location)
        menu.addAction(open_location_action)
        
        # Show the menu
        menu.exec_(self.process_table.mapToGlobal(position))
    
    def show_connection_context_menu(self, position):
        """Show context menu for connection table
        
        Args:
            position: Mouse position for menu display
        """
        menu = QMenu(self)
        
        # Get selected item
        selected_items = self.connections_table.selectedItems()
        if not selected_items:
            return
        
        # Get the row
        row = selected_items[0].row()
        
        # Add menu items
        copy_local_action = QAction("Copy Local Address", self)
        copy_local_action.triggered.connect(lambda: self.copy_connection_info("local"))
        menu.addAction(copy_local_action)
        
        copy_remote_action = QAction("Copy Remote Address", self)
        copy_remote_action.triggered.connect(lambda: self.copy_connection_info("remote"))
        menu.addAction(copy_remote_action)
        
        copy_all_action = QAction("Copy All", self)
        copy_all_action.triggered.connect(lambda: self.copy_connection_info("all"))
        menu.addAction(copy_all_action)
        
        # Show the menu
        menu.exec_(self.connections_table.mapToGlobal(position))
    
    def copy_process_info(self, field):
        """Copy process information to clipboard
        
        Args:
            field: Field to copy ("name" or "pid")
        """
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        
        if field == "name":
            text = self.process_table.item(row, 1).text()  # Name is column 1
        elif field == "pid":
            text = self.process_table.item(row, 2).text()  # PID is column 2
        else:
            text = ""
        
        # Copy to clipboard
        QApplication.clipboard().setText(text)
    
    def copy_connection_info(self, field):
        """Copy connection information to clipboard
        
        Args:
            field: Field to copy ("local", "remote" or "all")
        """
        selected_items = self.connections_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        
        if field == "local":
            text = self.connections_table.item(row, 0).text()  # Local address is column 0
        elif field == "remote":
            text = self.connections_table.item(row, 1).text()  # Remote address is column 1
        elif field == "all":
            local = self.connections_table.item(row, 0).text()
            remote = self.connections_table.item(row, 1).text()
            protocol = self.connections_table.item(row, 2).text()
            time = self.connections_table.item(row, 3).text()
            text = f"Local: {local}, Remote: {remote}, Protocol: {protocol}, Time: {time}"
        else:
            text = ""
        
        # Copy to clipboard
        QApplication.clipboard().setText(text)
    
    def open_process_location(self):
        """Open the folder containing the process executable"""
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        pid_item = self.process_table.item(row, 2)
        if not pid_item:
            return
        
        pid = int(pid_item.text())
        
        try:
            proc = psutil.Process(pid)
            path = proc.exe()
            
            if path and os.path.exists(path):
                folder = os.path.dirname(path)
                subprocess.Popen(f'explorer "{folder}"')
            else:
                QMessageBox.warning(self, "Warning", "Unable to find process location.")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            QMessageBox.warning(self, "Warning", f"Cannot access process: {e}")
    
    def toggle_sniffing(self):
        """Start or stop packet sniffing"""
        if not self.selected_pid:
            QMessageBox.warning(self, "Warning", "Please select a process first.")
            return
        
        if self.sniffing:
            # Only stop if actually running
            self.packet_text.append("Requesting sniffing to stop...")
            
            # Set flags first
            self.sniffing = False
            
            # Stop the thread if it exists and is running
            if self.sniffer_thread and self.sniffer_thread.isRunning():
                # Disconnect all signals to prevent callbacks during shutdown
                try:
                    self.sniffer_thread.packet_captured.disconnect()
                    self.sniffer_thread.error_occurred.disconnect()
                    self.sniffer_thread.status_update.disconnect()
                except:
                    pass  # It's okay if they're already disconnected
                
                # Stop the thread
                self.sniffer_thread.stop()
                
                # Wait for thread to stop
                if not self.sniffer_thread.wait(2000):  # Wait up to 2 seconds
                    self.packet_text.append("WARNING: Thread did not exit cleanly, may have to force quit")
                
                # Clear the reference
                self.sniffer_thread = None
                
            # Update UI
            self.start_sniff_btn.setText("Start Sniffing")
            self.packet_text.append("Sniffing stopped.")
        else:
            # Start sniffing only if not already running
            if self.sniffer_thread and self.sniffer_thread.isRunning():
                QMessageBox.warning(self, "Warning", "Sniffer is already running.")
                return
                
            # Update flags
            self.sniffing = True
            self.start_sniff_btn.setText("Stop Sniffing")
            
            # Clear existing data
            self.clear_sniff_data()
            
            try:
                # Get process connections
                proc = psutil.Process(self.selected_pid)
                
                # Use net_connections() instead of connections() (fix deprecation warning)
                proc_connections = proc.net_connections(kind='inet')
                local_ports = [conn.laddr.port for conn in proc_connections if hasattr(conn, 'laddr') and conn.laddr]
                
                # Add a status message
                self.packet_text.append(f"Starting packet capture for PID {self.selected_pid}...")
                if local_ports:
                    self.packet_text.append(f"Monitoring ports: {', '.join(map(str, local_ports))}")
                else:
                    self.packet_text.append("No active ports found. Will attempt to capture any traffic.")
                
                # Create new thread
                self.sniffer_thread = SnifferThread(self.selected_pid, local_ports)
                
                # Connect signals - use Qt.QueuedConnection to ensure thread safety
                self.sniffer_thread.packet_captured.connect(self.on_packet_captured, Qt.QueuedConnection)
                self.sniffer_thread.error_occurred.connect(self.on_sniffer_error, Qt.QueuedConnection)
                self.sniffer_thread.status_update.connect(self.on_sniffer_status, Qt.QueuedConnection)
                
                # Start thread
                self.sniffer_thread.start()
                
                # Set thread priority after thread is started to avoid the warning
                if self.sniffer_thread.isRunning():
                    self.sniffer_thread.setPriority(QThread.HighPriority)
                
            except Exception as e:
                self.packet_text.append(f"ERROR: {str(e)}")
                QMessageBox.critical(self, "Error", f"Error while starting sniffer: {e}")
                self.sniffing = False
                self.start_sniff_btn.setText("Start Sniffing")
    
    def on_sniffer_error(self, error_msg):
        """Handle errors from the sniffer thread
        
        Args:
            error_msg: Error message to display
        """
        # Log the error in the packet details area
        self.packet_text.append(f"ERROR: {error_msg}")
        
        # Only show a message box for critical errors
        if "No active ports" in error_msg:
            QMessageBox.warning(self, "Sniffer Warning", error_msg)
    
    def on_sniffer_status(self, status_msg):
        """Handle status updates from the sniffer thread
        
        Args:
            status_msg: Status message to display
        """
        # Log the status update in the packet details area with timestamp
        current_time = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.packet_text.append(f"[{current_time}] STATUS: {status_msg}")
    
    def on_packet_captured(self, packet_data):
        """Handle captured packet data
        
        Args:
            packet_data: Dictionary containing packet information
        """
        # Add to our data list
        self.sniff_data.append(packet_data)
        
        # Add to the table
        row = self.sniffer_table.rowCount()
        self.sniffer_table.insertRow(row)
        
        # Time
        time_item = QTableWidgetItem(packet_data["time"])
        self.sniffer_table.setItem(row, 0, time_item)
        
        # Source
        source_item = QTableWidgetItem(packet_data["source"])
        self.sniffer_table.setItem(row, 1, source_item)
        
        # Destination
        dest_item = QTableWidgetItem(packet_data["destination"])
        self.sniffer_table.setItem(row, 2, dest_item)
        
        # Protocol
        proto_item = QTableWidgetItem(packet_data["protocol"])
        proto_item.setTextAlignment(Qt.AlignCenter)
        self.sniffer_table.setItem(row, 3, proto_item)
        
        # Length
        length_item = QTableWidgetItem(str(packet_data["length"]))
        length_item.setTextAlignment(Qt.AlignCenter)
        self.sniffer_table.setItem(row, 4, length_item)
        
        # Auto-scroll to the bottom
        self.sniffer_table.scrollToBottom()
    
    def on_packet_select(self):
        """Handle packet selection in the sniffer table"""
        selected_items = self.sniffer_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        if 0 <= row < len(self.sniff_data):
            packet_data = self.sniff_data[row]
            raw_data = packet_data["raw"]
            
            # Clear and display packet details
            self.packet_text.clear()
            
            # Create detailed text
            details = f"Time: {packet_data['time']}\n"
            details += f"Source: {packet_data['source']}\n"
            details += f"Destination: {packet_data['destination']}\n"
            details += f"Protocol: {packet_data['protocol']}\n"
            details += f"Length: {packet_data['length']} bytes\n\n"
            details += "Hex Dump:\n"
            
            # Add hex dump
            offset = 0
            while offset < len(raw_data):
                # Get 16 bytes chunk
                chunk = raw_data[offset:offset+16]
                hex_dump = ' '.join(f"{b:02x}" for b in chunk)
                
                # Format printable ASCII
                ascii_dump = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                
                # Add line
                details += f"{offset:04x}:  {hex_dump:<48}  {ascii_dump}\n"
                offset += 16
            
            # Set the text
            self.packet_text.setText(details)
    
    def clear_sniff_data(self):
        """Clear sniffed packet data"""
        self.sniff_data = []
        self.sniffer_table.setRowCount(0)
        self.packet_text.clear()
    
    def save_sniff_data(self, format_type):
        """Save sniffed packet data to a file
        
        Args:
            format_type: Either "raw" (PCAP) or "csv"
        """
        if not self.sniff_data:
            QMessageBox.warning(self, "Warning", "No packet data to save.")
            return
        
        try:
            if format_type == "raw":
                # Save as pcap
                file_path, _ = QFileDialog.getSaveFileName(
                    self, "Save PCAP File", "", "PCAP Files (*.pcap);;All Files (*)"
                )
                
                if file_path:
                    packets = [Ether(data["raw"]) for data in self.sniff_data]
                    wrpcap(file_path, packets)
                    QMessageBox.information(self, "Success", f"Saved {len(packets)} packets to {file_path}")
            
            else:  # CSV
                file_path, _ = QFileDialog.getSaveFileName(
                    self, "Save CSV File", "", "CSV Files (*.csv);;All Files (*)"
                )
                
                if file_path:
                    with open(file_path, 'w', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(["Time", "Source", "Destination", "Protocol", "Length"])
                        
                        for packet in self.sniff_data:
                            writer.writerow([
                                packet["time"],
                                packet["source"],
                                packet["destination"],
                                packet["protocol"],
                                packet["length"]
                            ])
                    
                    QMessageBox.information(self, "Success", f"Saved {len(self.sniff_data)} records to {file_path}")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error saving file: {e}")
    
    def closeEvent(self, event):
        """Handle application close event
        
        Args:
            event: Close event
        """
        # Stop monitoring thread
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread.wait(1000)  # Wait up to 1 second
        
        # Stop sniffer thread
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait(1000)  # Wait up to 1 second
        
        # Accept the close event
        event.accept()


#-------------------------------------------------------------------------------
# Application Entry Point
#-------------------------------------------------------------------------------

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    window = NetworkMonitor()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()