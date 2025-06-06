import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
    QVBoxLayout, QHBoxLayout, QComboBox, QTabWidget, QCheckBox,
    QFileDialog, QScrollArea, QGroupBox
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QProcess

class NmapByAsh(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nmap by Ash - Advanced Nmap GUI")
        self.resize(1000, 800)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_tab("Basic Scanning", [
            ("Ping Scan (-sn)", "Enable ping scan to discover hosts"),
            ("Disable Ping (-Pn)", "Skip host discovery")
        ]), "Basic Scanning")

        self.tabs.addTab(self.create_tab("Host & Network Discovery", [
            ("ARP Ping (-PR)", "Use ARP requests for discovery"),
            ("ICMP Echo (-PE)", "Send ICMP echo requests")
        ]), "Host Discovery")

        self.tabs.addTab(self.create_tab("Port Selection & Scanning", [
            ("TCP SYN Scan (-sS)", "Perform a TCP SYN scan"),
            ("TCP Connect Scan (-sT)", "Perform a TCP connect scan"),
            ("UDP Scan (-sU)", "UDP port scan")
        ], port_input=True), "Port Scanning")

        self.tabs.addTab(self.create_tab("Service & OS Detection", [
            ("Version Detection (-sV)", "Detect service versions"),
            ("OS Detection (-O)", "Attempt OS detection")
        ]), "Service/OS Detection")

        self.tabs.addTab(self.create_tab("Output, Timing & Performance", [
            ("Normal Output (-oN)", "Save normal output"),
            ("XML Output (-oX)", "Save XML output")
        ], combo_options=[
            ("Timing Template", ["T0", "T1", "T2", "T3", "T4", "T5"])
        ]), "Output & Timing")

        self.tabs.addTab(self.create_tab("Firewall & IDS Evasion", [
            ("Fragment Packets (-f)", "Split packets to evade detection"),
            ("Decoy Scan (--decoy)", "Use decoy IPs for stealth"),
            ("Spoof MAC (--spoof-mac)", "Change MAC address")
        ]), "Firewall Evasion")

        self.tabs.addTab(self.create_tab("NSE Script Engine", [
            ("Enable NSE (--script)", "Run default NSE scripts")
        ], combo_options=[
            ("Script Category", ["auth", "default", "discovery", "dos", "exploit", "external", "fuzzer", "intrusive", "malware", "safe", "version", "vuln"])
        ]), "NSE Engine")

        self.tabs.addTab(self.create_tab("Advanced Targeting", [
            ("IPv6 Scan (-6)", "Scan IPv6 targets")
        ]), "Target Spec")

        self.tabs.addTab(self.create_tab("Performance Tuning", [
            ("Max Parallelism (--min-parallelism)", "Set minimum parallel tasks"),
            ("Scan Delay (--scan-delay)", "Add delay between probes")
        ]), "Performance")

        self.tabs.addTab(self.create_tab("Scripting & Automation", [
            ("Resume Scan (--resume)", "Resume previous scan"),
            ("Verbose (-v)", "Increase output verbosity"),
            ("Debug Mode (-d)", "Enable debug output")
        ]), "Automation")

        # Final UI
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target IP or Domain")

        self.scan_button = QPushButton("START SCAN")
        self.scan_button.clicked.connect(self.start_scan)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Target IP / Domain"))
        layout.addWidget(self.target_input)
        layout.addWidget(self.tabs)
        layout.addWidget(self.scan_button)
        layout.addWidget(QLabel("Output"))
        layout.addWidget(self.output_area)

        self.setLayout(layout)

        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.scan_finished)

    def create_tab(self, title, checkboxes, port_input=False, combo_options=None):
        tab = QWidget()
        layout = QVBoxLayout()
        self.__dict__[f"{title.lower().replace(' ', '_')}_boxes"] = []

        if port_input:
            self.port_input = QLineEdit()
            self.port_input.setPlaceholderText("e.g. 22,80,443 or 1-1000")
            layout.addWidget(QLabel("Port Range"))
            layout.addWidget(self.port_input)

        for text, tooltip in checkboxes:
            box = QCheckBox(text)
            box.setToolTip(tooltip)
            layout.addWidget(box)
            self.__dict__[f"{title.lower().replace(' ', '_')}_boxes"].append(box)

        if combo_options:
            for label, items in combo_options:
                layout.addWidget(QLabel(label))
                combo = QComboBox()
                combo.addItems(items)
                layout.addWidget(combo)
                self.__dict__[f"{label.lower().replace(' ', '_')}_combo"] = combo

        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def start_scan(self):
        self.output_area.clear()
        cmd = ["nmap"]
        target = self.target_input.text().strip()
        if not target:
            self.output_area.append("Please specify a target.")
            return

        for attr in dir(self):
            if attr.endswith("_boxes"):
                for box in getattr(self, attr):
                    if box.isChecked():
                        option = box.text().split()[1]
                        if "decoy" in box.text():
                            cmd.extend(["--decoy", "ME,1.2.3.4"])
                        elif "spoof-mac" in box.text():
                            cmd.extend(["--spoof-mac", "0"])
                        elif "resume" in box.text():
                            cmd.extend(["--resume", "scan.txt"])
                        elif "min-parallelism" in box.text():
                            cmd.extend(["--min-parallelism", "10"])
                        elif "scan-delay" in box.text():
                            cmd.extend(["--scan-delay", "1s"])
                        elif "--script" in box.text():
                            cmd.append("--script=default")
                        else:
                            cmd.append(option)

        if hasattr(self, "port_input") and self.port_input.text().strip():
            cmd.extend(["-p", self.port_input.text().strip()])

        if hasattr(self, "timing_template_combo"):
            cmd.append(f"-{self.timing_template_combo.currentText()}")

        cmd.append(target)
        self.output_area.append("Running: " + " ".join(cmd))
        self.scan_button.setEnabled(False)
        self.process.start(cmd[0], cmd[1:])

    def handle_stdout(self):
        data = self.process.readAllStandardOutput().data().decode()
        self.output_area.append(data)

    def handle_stderr(self):
        data = self.process.readAllStandardError().data().decode()
        self.output_area.append("ERROR: " + data)

    def scan_finished(self):
        self.output_area.append("\nScan completed.")
        self.scan_button.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NmapByAsh()
    window.show()
    sys.exit(app.exec())
