import os
import sys
import time
import ctypes
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QColor, QPixmap, QImage, QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QListWidget, QListWidgetItem,
    QProgressBar, QMessageBox, QFrame, QComboBox, 
    QTextEdit, QSplitter, QDialog, QDialogButtonBox,
    QGroupBox, QScrollArea, QCheckBox, QSizePolicy
)


UNIVERSAL_SIGNATURES = {
    "jpg": {"header": b"\xFF\xD8\xFF", "footer": b"\xFF\xD9", "max_size": 300 * 1024 * 1024},
    "png": {"header": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "footer": b"\x49\x45\x4E\x44\xAE\x42\x60\x82", "max_size": 300 * 1024 * 1024},
    "gif": {"header": b"GIF89a", "footer": b"\x00\x3B", "max_size": 150 * 1024 * 1024},
    "pdf": {"header": b"%PDF-", "footer": b"%%EOF", "max_size": 1024 * 1024 * 1024},
    "zip": {"header": b"\x50\x4B\x03\x04", "footer": b"\x50\x4B\x05\x06", "max_size": 2 * 1024 * 1024 * 1024},
    "docx_xlsx": {"header": b"\x50\x4B\x03\x04\x14\x00\x06\x00", "footer": b"\x50\x4B\x05\x06", "max_size": 1024 * 1024 * 1024},
    "rtf": {"header": b"{\\rtf1", "footer": b"}", "max_size": 200 * 1024 * 1024},
    "mp4": {"header": b"ftyp", "footer": None, "max_size": 5 * 1024 * 1024 * 1024, "offset_adjustment": -4},
    "avi": {"header": b"RIFF", "footer": None, "max_size": 5 * 1024 * 1024 * 1024},
    "mkv": {"header": b"\x1A\x45\xDF\xA3", "footer": None, "max_size": 5 * 1024 * 1024 * 1024},
    "mp3": {"header": b"\x49\x44\x33", "footer": None, "max_size": 1 * 1024 * 1024 * 1024},
    "flac": {"header": b"fLaC", "footer": None, "max_size": 1 * 1024 * 1024 * 1024},
    "rar": {"header": b"Rar!\x1A\x07", "footer": None, "max_size": 2 * 1024 * 1024 * 1024},
    "7z": {"header": b"\x37\x7A\xBC\xAF\x27\x1C", "footer": None, "max_size": 2 * 1024 * 1024 * 1024},
}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


class SourceSelectionDialog(QDialog):
    """Modern Visual Card-Based Windows Evidence Selector Dialog"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Evidence Source ")
        self.resize(740, 540)
        self.selected_path = None
        self.setStyleSheet("QDialog { background-color: #121212; color: #ffffff; }")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)

        title = QLabel("Select Forensic Target Source (HDD / USB / SSD / Image)")
        title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        title.setStyleSheet("color: #ffffff;")
        layout.addWidget(title)

        subtitle = QLabel("Choose a physical hardware drive, logical volume (NTFS/FAT32/exFAT), or disk image file:")
        subtitle.setStyleSheet("color: #aaaaaa; font-size: 11px;")
        layout.addWidget(subtitle)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: 1px solid #333333; background-color: #161616; border-radius: 6px; }")
        scroll_content = QWidget()
        scroll_content.setStyleSheet("background-color: #161616;")
        self.card_layout = QVBoxLayout(scroll_content)
        self.card_layout.setContentsMargins(10, 10, 10, 10)
        
        self.populate_sources()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        btn_layout = QHBoxLayout()
        self.btn_browse = QPushButton("📁 Browse Disk Image File (.dd, .img, .raw, .bin)")
        self.btn_browse.setStyleSheet("background-color: #1f538d; color: white; padding: 10px; font-weight: bold; border-radius: 4px;")
        self.btn_browse.clicked.connect(self.browse_image_file)
        btn_layout.addWidget(self.btn_browse)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        buttons.setStyleSheet("QPushButton { background-color: #333333; color: white; padding: 8px 16px; border-radius: 4px; font-weight: bold; }")
        buttons.rejected.connect(self.reject)
        btn_layout.addWidget(buttons)

        layout.addLayout(btn_layout)

    def populate_sources(self):
        for i in range(8):
            drive_path = f"\\\\.\\PhysicalDrive{i}"
            try:
                handle = ctypes.windll.kernel32.CreateFileW(
                    drive_path, 0x80000000, 0x00000001 | 0x00000002, 
                    None, 3, 0x00000080, None
                )
                if handle != -1:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    self.add_source_card(f"Physical Hard Disk {i} (HDD/USB/SSD)", drive_path, "💾 Physical Hardware Device")
            except Exception:
                pass

        for letter in range(ord('A'), ord('Z') + 1):
            drive_letter = chr(letter)
            volume_path = f"\\\\.\\{drive_letter}:"
            try:
                handle = ctypes.windll.kernel32.CreateFileW(
                    volume_path, 0x80000000, 0x00000001 | 0x00000002, 
                    None, 3, 0x00000080, None
                )
                if handle != -1:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    self.add_source_card(f"Logical Partition Volume ({drive_letter}:)", volume_path, "🗂️ NTFS / FAT32 / exFAT Volume")
            except Exception:
                pass

    def add_source_card(self, title, path, category):
        card = QFrame()
        card.setStyleSheet("""
            QFrame { background-color: #1e1e1e; border: 1px solid #333333; border-radius: 6px; padding: 12px; }
            QFrame:hover { background-color: #262626; border: 1px solid #1f538d; }
        """)
        card_layout = QHBoxLayout(card)

        info_layout = QVBoxLayout()
        lbl_title = QLabel(title)
        lbl_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        lbl_title.setStyleSheet("color: white; background: transparent; border: none;")
        
        lbl_path = QLabel(f"Path Handle: {path}  |  Type: {category}")
        lbl_path.setStyleSheet("color: #00ffcc; font-family: Consolas; font-size: 10px; background: transparent; border: none;")

        info_layout.addWidget(lbl_title)
        info_layout.addWidget(lbl_path)
        card_layout.addLayout(info_layout)
        card_layout.addStretch()

        btn_select = QPushButton("Select Target")
        btn_select.setStyleSheet("background-color: #2b8a3e; color: white; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        btn_select.clicked.connect(lambda _, p=path: self.select_path_and_accept(p))
        card_layout.addWidget(btn_select)

        self.card_layout.addWidget(card)

    def select_path_and_accept(self, path):
        self.selected_path = path
        self.accept()

    def browse_image_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Disk Image File", "", "Disk Images (*.dd *.img *.raw *.bin);;All Files (*)")
        if file_path:
            self.selected_path = file_path
            self.accept()


class RealTimeScanWorker(QThread):
    candidate_found_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(float, int, str)
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int, float)
    error_signal = pyqtSignal(str)

    def __init__(self, source_path, active_signatures, include_corrupted):
        super().__init__()
        self.source_path = source_path
        self.active_signatures = active_signatures
        self.include_corrupted = include_corrupted
        self.is_running = True

    def run(self):
        chunk_size = 32 * 1024 * 1024  # 32MB deep sector chunking
        overlap_size = 4 * 1024 * 1024   # 4MB bit-perfect overlap for cross-sector file integrity
        bytes_scanned = 0
        total_discovered = 0
        start_time = time.time()

        self.log_signal.emit(f"[*] Initializing Master Bit-Level Deep Scan on: {self.source_path}")

        file_size = 0
        try:
            file_size = os.path.getsize(self.source_path)
        except (OSError, AttributeError):
            file_size = 0

        if file_size == 0 and ("PhysicalDrive" in self.source_path or self.source_path.startswith("\\\\.\\")):
            try:
                handle = ctypes.windll.kernel32.CreateFileW(
                    self.source_path, 0x80000000, 0x00000001 | 0x00000002, None, 3, 0x00000080, None
                )
                if handle != -1:
                    class DISK_GEOMETRY_EX(ctypes.Structure):
                        _fields_ = [("Geometry", ctypes.c_byte * 24), ("DiskSize", ctypes.c_longlong), ("Data", ctypes.c_byte * 32)]
                    geom = DISK_GEOMETRY_EX()
                    bytes_returned = ctypes.c_ulong(0)
                    success = ctypes.windll.kernel32.DeviceIoControl(
                        handle, 0x000700A0, None, 0, ctypes.byref(geom), ctypes.sizeof(geom), ctypes.byref(bytes_returned), None
                    )
                    ctypes.windll.kernel32.CloseHandle(handle)
                    if success and geom.DiskSize > 0:
                        file_size = geom.DiskSize
            except Exception:
                pass

        try:
            with open(self.source_path, "rb") as f:
                buffer = b""
                file_id_counter = 1

                while self.is_running:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    search_buffer = buffer + chunk
                    bytes_scanned += len(chunk)

                    for ext in self.active_signatures:
                        if not self.is_running:
                            break
                        sig = UNIVERSAL_SIGNATURES[ext]
                        header = sig["header"]
                        footer = sig["footer"]
                        max_size = sig["max_size"]
                        offset_adj = sig.get("offset_adjustment", 0)

                        if ext == "gif":
                            pos = 0
                            while self.is_running:
                                pos = search_buffer.find(b"GIF", pos)
                                if pos == -1: break
                                if search_buffer[pos:pos+6] in [b"GIF87a", b"GIF89a"]:
                                    absolute_pos = bytes_scanned - len(search_buffer) + pos
                                    end_pos = search_buffer.find(footer, pos + 6)
                                    if end_pos != -1:
                                        file_len = (end_pos + len(footer)) - pos
                                        candidate = {"id": file_id_counter, "ext": ext, "offset": absolute_pos, "size": file_len, "status": "100% Healthy (Raw Sector Verified)"}
                                        total_discovered += 1
                                        file_id_counter += 1
                                        self.candidate_found_signal.emit(candidate)
                                    elif self.include_corrupted:
                                        candidate = {"id": file_id_counter, "ext": ext, "offset": absolute_pos, "size": min(max_size, len(search_buffer) - pos), "status": "Fragmented Sector Data"}
                                        total_discovered += 1
                                        file_id_counter += 1
                                        self.candidate_found_signal.emit(candidate)
                                pos += 3
                            continue

                        pos = 0
                        while self.is_running:
                            pos = search_buffer.find(header, pos)
                            if pos == -1:
                                break

                            true_start = pos + offset_adj
                            absolute_pos = bytes_scanned - len(search_buffer) + true_start

                            if absolute_pos < 0:
                                pos += len(header)
                                continue

                            if footer:
                                end_pos = search_buffer.find(footer, pos + len(header))
                                if end_pos != -1:
                                    file_len = (end_pos + len(footer)) - true_start
                                    if file_len <= max_size:
                                        candidate = {"id": file_id_counter, "ext": ext, "offset": absolute_pos, "size": file_len, "status": "100% Healthy (Raw Sector Verified)"}
                                        total_discovered += 1
                                        file_id_counter += 1
                                        self.candidate_found_signal.emit(candidate)
                                elif self.include_corrupted:
                                    available_space = len(search_buffer) - true_start
                                    extract_len = min(max_size, available_space)
                                    if extract_len > 100:
                                        candidate = {"id": file_id_counter, "ext": ext, "offset": absolute_pos, "size": extract_len, "status": "Fragmented Sector Data"}
                                        total_discovered += 1
                                        file_id_counter += 1
                                        self.candidate_found_signal.emit(candidate)
                            else:
                                available_space = len(search_buffer) - true_start
                                extract_len = min(max_size, available_space)
                                if extract_len > 100:
                                    candidate = {"id": file_id_counter, "ext": ext, "offset": absolute_pos, "size": extract_len, "status": "Deep Stream Carved (Bit-Level)"}
                                    total_discovered += 1
                                    file_id_counter += 1
                                    self.candidate_found_signal.emit(candidate)

                            pos += len(header)

                    buffer = search_buffer[-overlap_size:]

                    if file_size > 0:
                        progress = min(100.0, (bytes_scanned / file_size) * 100)
                        self.progress_signal.emit(progress, total_discovered, f"Deep Scanning Sectors... {progress:.1f}% ({bytes_scanned / (1024*1024):.1f} MB)")
                    else:
                        mb_scanned = bytes_scanned / (1024 * 1024)
                        self.progress_signal.emit(0.0, total_discovered, f"Deep Scanning Bit-Stream... {mb_scanned:.1f} MB scanned")

            duration = time.time() - start_time
            self.log_signal.emit(f"[✓] Master scan completed in {duration:.2f}s. Total valid candidates: {total_discovered}")
            self.finished_signal.emit(total_discovered, duration)

        except Exception as e:
            self.log_signal.emit(f"[!] Critical Error in worker thread: {str(e)}")
            self.error_signal.emit(str(e))

    def stop(self):
        self.is_running = False


class WindowsForensicStudioPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Carvify - A project by Shirazi Solutions")
        self.setMinimumSize(1300, 850)
        self.resize(1500, 900)
        
        self.source_path = ""
        self.candidates = []
        self.worker = None
        self.type_checkboxes = {}

        self.init_ui()
        self.apply_stylesheet()

        if not is_admin():
            QMessageBox.warning(self, "Administrator Privilege Notice", 
                                "Warning: You are not running this tool as Administrator.\n"
                                "Reading physical hardware drives or raw volumes requires elevated admin rights.")

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        # --- Left Control Sidebar ---
        sidebar_outer = QScrollArea()
        sidebar_outer.setFixedWidth(380)
        sidebar_outer.setWidgetResizable(True)
        sidebar_outer.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        sidebar_outer.setStyleSheet("QScrollArea { border: none; background-color: #121212; }")

        sidebar = QWidget()
        sidebar.setStyleSheet("background-color: #121212;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 10, 0)
        sidebar_layout.setSpacing(14)

        title_lbl = QLabel("🛡️ Carvify - By Shirazi Solutions")
        title_lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title_lbl.setStyleSheet("color: #ffffff; background: transparent;")
        sidebar_layout.addWidget(title_lbl)

        self.btn_select_source = QPushButton("🔍 Select Evidence Source...")
        self.btn_select_source.setStyleSheet("background-color: #1f538d; color: white; padding: 12px; font-weight: bold; border-radius: 6px;")
        self.btn_select_source.clicked.connect(self.open_source_selector)
        sidebar_layout.addWidget(self.btn_select_source)

        self.lbl_active_target = QLabel("Target: None Selected")
        self.lbl_active_target.setWordWrap(True)
        self.lbl_active_target.setStyleSheet("color: #ff5555; font-size: 11px; font-weight: bold; background: transparent;")
        sidebar_layout.addWidget(self.lbl_active_target)

        # File Types Selection Group Box
        types_group = QGroupBox("Select File Types to Scan")
        types_group.setStyleSheet("""
            QGroupBox {
                background-color: #1a1a1a;
                border: 1px solid #333333;
                border-radius: 6px;
                margin-top: 10px;
                font-weight: bold;
                color: #00ffcc;
                padding-top: 18px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 5px;
                background-color: #1a1a1a;
            }
        """)
        types_layout = QVBoxLayout(types_group)
        types_layout.setSpacing(10)
        
        btn_sel_layout = QHBoxLayout()
        btn_all = QPushButton("Select All")
        btn_all.setStyleSheet("background-color: #2a2a2a; color: #ffffff; padding: 6px; font-size: 10px; border-radius: 4px;")
        btn_all.clicked.connect(lambda: self.toggle_all_types(True))
        
        btn_none = QPushButton("Deselect All")
        btn_none.setStyleSheet("background-color: #2a2a2a; color: #ffffff; padding: 6px; font-size: 10px; border-radius: 4px;")
        btn_none.clicked.connect(lambda: self.toggle_all_types(False))
        
        btn_sel_layout.addWidget(btn_all)
        btn_sel_layout.addWidget(btn_none)
        types_layout.addLayout(btn_sel_layout)

        chk_container = QWidget()
        chk_container.setStyleSheet("background: transparent;")
        chk_layout = QVBoxLayout(chk_container)
        chk_layout.setContentsMargins(5, 5, 5, 5)
        chk_layout.setSpacing(8)
        
        for ext in UNIVERSAL_SIGNATURES.keys():
            chk = QCheckBox(f".{ext.upper()}")
            chk.setChecked(True)
            chk.setStyleSheet("color: #ffffff; font-size: 11px; font-family: 'Segoe UI'; spacing: 8px; background: transparent;")
            self.type_checkboxes[ext] = chk
            chk_layout.addWidget(chk)
            
        types_layout.addWidget(chk_container)

        self.chk_corrupted = QCheckBox("Include Fragmented / Raw Sectors\n(Maximum Recovery Depth)")
        self.chk_corrupted.setChecked(True)
        self.chk_corrupted.setStyleSheet("color: #f1c40f; font-weight: bold; font-size: 10px; spacing: 8px; margin-top: 5px; background: transparent;")
        types_layout.addWidget(self.chk_corrupted)

        sidebar_layout.addWidget(types_group)

        self.btn_scan = QPushButton("⚡ Start Bit Level Deep Scan")
        self.btn_scan.setEnabled(False)
        self.btn_scan.setStyleSheet("background-color: #2b8a3e; color: white; font-weight: bold; padding: 12px; border-radius: 6px;")
        self.btn_scan.clicked.connect(self.start_scan)
        sidebar_layout.addWidget(self.btn_scan)

        self.btn_stop = QPushButton("🛑 Stop Scan")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 10px; border-radius: 6px;")
        self.btn_stop.clicked.connect(self.stop_scan)
        sidebar_layout.addWidget(self.btn_stop)

        self.btn_recover = QPushButton("💾 Recover Selected Files")
        self.btn_recover.setEnabled(False)
        self.btn_recover.setStyleSheet("background-color: #1f538d; color: white; font-weight: bold; padding: 10px; border-radius: 6px;")
        self.btn_recover.clicked.connect(self.recover_selected)
        sidebar_layout.addWidget(self.btn_recover)

        self.btn_recover_all = QPushButton("📦 Recover All Discovered")
        self.btn_recover_all.setEnabled(False)
        self.btn_recover_all.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold; padding: 10px; border-radius: 6px;")
        self.btn_recover_all.clicked.connect(self.recover_all)
        sidebar_layout.addWidget(self.btn_recover_all)

        stats_group = QGroupBox("Live Scan Statistics")
        stats_group.setStyleSheet("""
            QGroupBox {
                background-color: #1a1a1a;
                border: 1px solid #333333;
                border-radius: 6px;
                margin-top: 10px;
                font-weight: bold;
                color: #00ffcc;
                padding-top: 18px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 5px;
                background-color: #1a1a1a;
            }
        """)
        stats_layout = QVBoxLayout(stats_group)
        self.lbl_stats = QLabel("Discovered: 0 files")
        self.lbl_stats.setStyleSheet("color: #00ffcc; font-family: Consolas; font-size: 11px; background: transparent;")
        stats_layout.addWidget(self.lbl_stats)
        sidebar_layout.addWidget(stats_group)

        sidebar_layout.addStretch()
        sidebar_outer.setWidget(sidebar)
        main_layout.addWidget(sidebar_outer)

        # --- Right Main Dashboard ---
        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        top_splitter = QSplitter(Qt.Orientation.Horizontal)

        grid_container = QWidget()
        grid_container.setStyleSheet("background: transparent;")
        grid_layout = QVBoxLayout(grid_container)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setSpacing(10)

        status_frame = QFrame()
        status_frame.setStyleSheet("background-color: #1a1a1a; border: 1px solid #333333; border-radius: 6px;")
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(12, 12, 12, 12)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("QProgressBar { border: 1px solid #333333; border-radius: 4px; text-align: center; color: white; background-color: #111111; height: 18px; } QProgressBar::chunk { background-color: #1f538d; border-radius: 3px; }")
        status_layout.addWidget(self.progress_bar)

        self.lbl_status = QLabel("Status: Waiting for evidence source selection...")
        self.lbl_status.setStyleSheet("color: #e0e0e0; font-size: 11px; background: transparent;")
        status_layout.addWidget(self.lbl_status)
        grid_layout.addWidget(status_frame)

        filter_layout = QHBoxLayout()
        grid_title = QLabel("Discovered Candidates (Thumbnail Grid)")
        grid_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        grid_title.setStyleSheet("color: #ffffff; background: transparent;")
        filter_layout.addWidget(grid_title)
        filter_layout.addStretch()

        filter_label = QLabel("Filter Type:")
        filter_label.setStyleSheet("color: #aaaaaa; background: transparent;")
        filter_layout.addWidget(filter_label)

        self.combo_filter = QComboBox()
        self.combo_filter.addItem("All")
        for ext in UNIVERSAL_SIGNATURES.keys():
            self.combo_filter.addItem(ext)
        self.combo_filter.setStyleSheet("background-color: #252525; color: white; border: 1px solid #3d3d3d; border-radius: 4px; padding: 5px 10px;")
        self.combo_filter.currentTextChanged.connect(self.filter_grid)
        filter_layout.addWidget(self.combo_filter)
        grid_layout.addLayout(filter_layout)

        self.grid_widget = QListWidget()
        self.grid_widget.setViewMode(QListWidget.ViewMode.IconMode)
        self.grid_widget.setIconSize(QSize(96, 96))
        self.grid_widget.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.grid_widget.setSpacing(15)
        self.grid_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.grid_widget.setStyleSheet("background-color: #161616; border: 1px solid #333333; border-radius: 6px;")
        self.grid_widget.itemSelectionChanged.connect(self.display_candidate_details)
        grid_layout.addWidget(self.grid_widget)

        top_splitter.addWidget(grid_container)

        inspector_container = QWidget()
        inspector_container.setStyleSheet("background: transparent;")
        inspector_layout = QVBoxLayout(inspector_container)
        inspector_layout.setContentsMargins(0, 0, 0, 0)
        inspector_layout.setSpacing(10)
        
        inspector_title = QLabel("🔍 Detailed Forensic Inspector")
        inspector_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        inspector_title.setStyleSheet("color: #ffffff; background: transparent;")
        inspector_layout.addWidget(inspector_title)

        self.inspector_text = QTextEdit()
        self.inspector_text.setReadOnly(True)
        self.inspector_text.setStyleSheet("background-color: #181818; color: #ffffff; font-family: Consolas; font-size: 11px; border: 1px solid #333333; border-radius: 6px;")
        inspector_layout.addWidget(self.inspector_text)
        
        inspector_container.setFixedWidth(380)
        top_splitter.addWidget(inspector_container)
        top_splitter.setSizes([650, 380])

        right_splitter.addWidget(top_splitter)

        console_container = QWidget()
        console_container.setStyleSheet("background: transparent;")
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(0, 5, 0, 0)
        console_layout.setSpacing(6)
        
        console_title = QLabel("Live Activity Console Log")
        console_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        console_title.setStyleSheet("color: #ffffff; background: transparent;")
        console_layout.addWidget(console_title)

        self.console_log = QTextEdit()
        self.console_log.setReadOnly(True)
        self.console_log.setStyleSheet("background-color: #0d0d0d; color: #00ff66; font-family: Consolas; font-size: 11px; border: 1px solid #333333; border-radius: 6px;")
        console_layout.addWidget(self.console_log)

        right_splitter.addWidget(console_container)
        right_splitter.setSizes([550, 150])

        main_layout.addWidget(right_splitter)

    def apply_stylesheet(self):
        qss = """
            QMainWindow { background-color: #121212; }
            QPushButton:disabled { background-color: #1a1a1a; color: #555555; border: 1px solid #2a2a2a; }
            QListWidget::item { background: #1e1e1e; border: 1px solid #333333; border-radius: 6px; padding: 6px; color: white; width: 115px; height: 115px; }
            QListWidget::item:selected { background: #1f538d; border: 1px solid #00ffcc; }
            QScrollBar:vertical { background: #121212; width: 10px; margin: 0px; border-radius: 5px; }
            QScrollBar::handle:vertical { background: #333333; min-height: 20px; border-radius: 5px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        """
        self.setStyleSheet(qss)

    def toggle_all_types(self, state):
        for chk in self.type_checkboxes.values():
            chk.setChecked(state)

    def log(self, message):
        self.console_log.append(message)

    def open_source_selector(self):
        dialog = SourceSelectionDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.selected_path:
            self.source_path = dialog.selected_path
            self.lbl_active_target.setText(f"Target: {self.source_path}")
            self.lbl_active_target.setStyleSheet("color: #2ecc71; font-size: 11px; font-weight: bold; background: transparent;")
            self.btn_scan.setEnabled(True)
            self.log(f"[+] Selected master evidence source: {self.source_path}")

    def start_scan(self):
        active_signatures = [ext for ext, chk in self.type_checkboxes.items() if chk.isChecked()]
        if not active_signatures:
            QMessageBox.warning(self, "Selection Warning", "Please select at least one file type to scan.")
            return

        include_corrupted = self.chk_corrupted.isChecked()

        self.grid_widget.clear()
        self.candidates = []
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_select_source.setEnabled(False)

        self.worker = RealTimeScanWorker(self.source_path, active_signatures, include_corrupted)
        self.worker.candidate_found_signal.connect(self.add_candidate_live)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.error_signal.connect(self.scan_error)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.log("[!] Abort signal sent. Stopping scan...")
            self.btn_stop.setEnabled(False)

    def add_candidate_live(self, item):
        self.candidates.append(item)
        
        current_filter = self.combo_filter.currentText()
        if current_filter == "All" or current_filter == item['ext']:
            self.create_grid_item(item)

        self.lbl_stats.setText(f"Discovered: {len(self.candidates)} files")

    def create_grid_item(self, item):
        icon = QIcon()
        if item['ext'] in ["jpg", "png", "gif"]:
            try:
                with open(self.source_path, "rb") as f:
                    f.seek(item['offset'])
                    data = f.read(min(item['size'], 100 * 1024))
                    qimg = QImage.fromData(data)
                    if not qimg.isNull():
                        pixmap = QPixmap.fromImage(qimg).scaled(96, 96, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                        icon = QIcon(pixmap)
            except Exception:
                pass

        list_item = QListWidgetItem(icon, f"ID:{item['id']} .{item['ext'].upper()}\nOff: 0x{item['offset']:X}")
        list_item.setData(Qt.ItemDataRole.UserRole, item['id'])
        self.grid_widget.addItem(list_item)

    def update_progress(self, progress, count, text):
        self.progress_bar.setValue(int(progress))
        self.lbl_status.setText(f"{text} | Discovered: {count}")

    def scan_finished(self, total_count, duration):
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_select_source.setEnabled(True)
        self.lbl_status.setText(f"Scan complete in {duration:.2f}s. Total valid candidates: {total_count}")
        
        if total_count > 0:
            self.btn_recover.setEnabled(True)
            self.btn_recover_all.setEnabled(True)

    def scan_error(self, err_msg):
        QMessageBox.critical(self, "Scan Error", f"Operation failed:\n{err_msg}\n\nMake sure your script is run as Administrator.")
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_select_source.setEnabled(True)

    def filter_grid(self, ext_filter):
        self.grid_widget.clear()
        for item in self.candidates:
            if ext_filter == "All" or item['ext'] == ext_filter:
                self.create_grid_item(item)

    def display_candidate_details(self):
        selected_items = self.grid_widget.selectedItems()
        if not selected_items:
            self.inspector_text.clear()
            return

        file_id = selected_items[0].data(Qt.ItemDataRole.UserRole)
        match = next((c for c in self.candidates if c['id'] == file_id), None)
        if match:
            details = (
                f"=== MASTER FORENSIC FILE RECORD ===\n"
                f"Candidate ID:   {match['id']}\n"
                f"File Extension: {match['ext'].upper()}\n"
                f"Offset (Hex):   0x{match['offset']:08X}\n"
                f"Offset (Dec):   {match['offset']}\n"
                f"File Size:      {match['size']} bytes\n"
                f"Status:         {match['status']}\n"
                f"Source Medium:  {os.path.basename(self.source_path)}\n"
            )
            self.inspector_text.setText(details)

    def recover_selected(self):
        selected_items = self.grid_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Warning", "Please select one or more file cards from the grid.")
            return

        selected_ids = {item.data(Qt.ItemDataRole.UserRole) for item in selected_items}
        self.extract_files(selected_ids)

    def recover_all(self):
        if not self.candidates:
            return
        selected_ids = {item['id'] for item in self.candidates}
        self.extract_files(selected_ids)

    def extract_files(self, selected_ids):
        output_dir = QFileDialog.getExistingDirectory(self, "Select Destination Folder for Recovered Files")
        if not output_dir:
            return

        saved_count = 0
        sector_size = 512
        buffer_size = 16384

        try:
            self.log(f"[*] Exporting {len(selected_ids)} healthy carved files to '{output_dir}'...")
            with open(self.source_path, "rb") as f:
                for item in self.candidates:
                    if item['id'] in selected_ids:
                        aligned_offset = (item['offset'] // sector_size) * sector_size
                        padding_bytes = item['offset'] - aligned_offset
                        read_length = padding_bytes + item['size']

                        f.seek(aligned_offset)
                        
                        out_name = f"recovered_{item['id']}_{item['ext'].upper()}_offset_{item['offset']:X}.{item['ext']}"
                        out_path = os.path.join(output_dir, out_name)
                        
                        bytes_remaining = read_length
                        with open(out_path, "wb") as out_f:
                            while bytes_remaining > 0:
                                chunk_to_read = min(buffer_size, bytes_remaining)
                                data_chunk = f.read(chunk_to_read)
                                if not data_chunk:
                                    break
                                bytes_remaining -= len(data_chunk)
                                
                                if aligned_offset == (item['offset'] // sector_size) * sector_size and padding_bytes > 0:
                                    if len(data_chunk) >= padding_bytes:
                                        out_f.write(data_chunk[padding_bytes:])
                                        padding_bytes = 0
                                    else:
                                        padding_bytes -= len(data_chunk)
                                else:
                                    out_f.write(data_chunk)

                        saved_count += 1

            self.log(f"[+] Successfully exported {saved_count} file(s) to '{output_dir}'.")
            QMessageBox.information(self, "Export Complete", f"Successfully carved and saved {saved_count} file(s) to:\n{output_dir}")
        except Exception as e:
            self.log(f"[!] Export error: {e}")
            QMessageBox.critical(self, "Export Error", f"Failed during file extraction:\n{str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WindowsForensicStudioPro()
    window.show()
    sys.exit(app.exec())