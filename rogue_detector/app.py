from __future__ import annotations

import sys
import threading
import time
from datetime import datetime

from PyQt6 import QtCore, QtWidgets

from .config import default_config
from .detector import DetectionEngine
from .platform_scanner import get_scanner, disconnect_wifi


class ScannerWorker(QtCore.QObject):
    scanCompleted = QtCore.pyqtSignal(list)
    suspiciousDetected = QtCore.pyqtSignal(list)
    statusChanged = QtCore.pyqtSignal(str)

    def __init__(self, engine, interval=6):
        super().__init__()
        self.engine = engine
        self.scanner = get_scanner()
        self.interval = max(2, interval)
        self.running = False
        self.stop_event = threading.Event()

    @QtCore.pyqtSlot()
    def run(self):
        self.running = True
        self.stop_event.clear()
        while self.running:
            try:
                networks = self.scanner.scan()
                connected = [ap for ap in networks if ap.is_connected]
                active = connected or networks
                events = self.engine.evaluate(active)
                self.scanCompleted.emit(active)
                if events:
                    self.suspiciousDetected.emit(events)
                status = "Нет подключенной сети" if not connected else "Последнее сканирование"
                self.statusChanged.emit(f"{status}: {datetime.now().strftime('%H:%M:%S')}")
            except Exception as exc:
                self.statusChanged.emit(f"Scan error: {exc}")
            if self.stop_event.wait(self.interval):
                break

    def stop(self):
        self.running = False
        self.stop_event.set()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.worker_thread = QtCore.QThread()
        self.worker = ScannerWorker(engine, interval=engine.config.scan_interval_sec)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.scanCompleted.connect(self.update_table)
        self.worker.suspiciousDetected.connect(self.show_alerts)
        self.worker.statusChanged.connect(self.set_status)
        self.last_scan = []
        self.setWindowTitle("Rogue AP Detector")
        self.resize(980, 680)
        self.build_ui()
        self.apply_style()

    def build_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        controls = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Старт мониторинга")
        self.stop_btn = QtWidgets.QPushButton("Стоп")
        self.scan_btn = QtWidgets.QPushButton("Разовое сканирование")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.scan_btn.clicked.connect(self.scan_once)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addWidget(self.scan_btn)
        controls.addStretch()
        layout.addLayout(controls)

        info_box = QtWidgets.QGroupBox("Текущая сеть")
        info_layout = QtWidgets.QGridLayout()
        info_layout.setContentsMargins(10, 18, 10, 10)
        self.info_labels = {}
        fields = [
            ("SSID", "—"),
            ("BSSID", "—"),
            ("Шифрование", "—"),
            ("Канал", "—"),
            ("Сигнал (%)", "—"),
            ("Диапазон", "—"),
            ("TX (Mbps)", "—"),
        ]
        for row, (key, label) in enumerate(fields):
            title = QtWidgets.QLabel(f"{key}:")
            title.setStyleSheet("color: #4a5568; font-weight: 600;")
            val = QtWidgets.QLabel(label)
            self.info_labels[key] = val
            info_layout.addWidget(title, row, 0)
            info_layout.addWidget(val, row, 1)
        info_box.setLayout(info_layout)
        layout.addWidget(info_box)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "SSID",
            "BSSID",
            "Сигнал (%)",
            "Канал",
            "Шифрование",
            "Диапазон",
            "TX (Mbps)",
            "Текущая",
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        self.alerts = QtWidgets.QListWidget()
        self.alerts.setMaximumHeight(180)
        layout.addWidget(QtWidgets.QLabel("Уведомления"))
        layout.addWidget(self.alerts)

        self.status_label = QtWidgets.QLabel("Готово")
        layout.addWidget(self.status_label)

        central.setLayout(layout)
        self.setCentralWidget(central)

    def apply_style(self):
        self.setStyleSheet(
            """
        QWidget { font-family: Arial; font-size: 14px; background: #f7f9fc; }
        QGroupBox { background: #fff; border-radius: 8px; }
        QPushButton { background: #2d6cdf; color: white; padding: 8px; border-radius: 6px; }
        QPushButton:disabled { background: #a5b4cb; }
        QTableWidget, QListWidget { background: #fff; border-radius: 8px; }
        """
        )

    def start_monitoring(self):
        if self.worker_thread.isRunning():
            return
        self.worker_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Мониторинг запущен")

    def stop_monitoring(self):
        if not self.worker_thread.isRunning():
            return
        self.worker.stop()
        self.worker_thread.quit()
        self.worker_thread.wait(max(3000, self.worker.interval * 1000 + 500))
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Мониторинг остановлен")

    def scan_once(self):
        networks = self.worker.scanner.scan()
        connected = [ap for ap in networks if ap.is_connected]
        active = connected or networks
        events = self.engine.evaluate(active)
        self.update_table(active)
        if events:
            self.show_alerts(events)
        self.set_status("Разовое сканирование завершено")

    def update_table(self, networks):
        ordered = sorted(networks, key=lambda ap: (not ap.is_connected, ap.ssid.lower()))
        self.last_scan = ordered
        self.table.setRowCount(len(ordered))
        for row, ap in enumerate(ordered):
            values = [
                ap.ssid,
                ap.bssid,
                self.format_signal(ap.signal),
                str(ap.channel) if ap.channel else "",
                ap.security,
                ap.band or "",
                f"{ap.tx_rate:.1f}" if ap.tx_rate else "",
                "Да" if ap.is_connected else "",
            ]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QtWidgets.QTableWidgetItem(value))
        self.table.resizeColumnsToContents()
        current = ordered[0] if ordered and ordered[0].is_connected else None
        self.info_labels["SSID"].setText(current.ssid if current else "—")
        self.info_labels["BSSID"].setText(current.bssid if current else "—")
        self.info_labels["Шифрование"].setText(current.security if current else "—")
        self.info_labels["Канал"].setText(str(current.channel) if current and current.channel else "—")
        self.info_labels["Сигнал (%)"].setText(self.format_signal(current.signal) if current else "—")
        self.info_labels["Диапазон"].setText(current.band if current and current.band else "—")
        self.info_labels["TX (Mbps)"].setText(f"{current.tx_rate:.1f}" if current and current.tx_rate else "—")

    def show_alerts(self, events):
        self.stop_monitoring()
        disconnect_wifi()
        severity_map = {"critical": "КРИТИЧНО", "medium": "ПРЕДУПРЕЖДЕНИЕ"}
        for event in events:
            sev = severity_map.get(event.severity, event.severity.upper())
            self.alerts.insertItem(0, f"[{event.timestamp:%H:%M:%S}] {sev}: {event.reason}")
        self.alerts.setCurrentRow(0)
        QtWidgets.QMessageBox.warning(
            self,
            "Предупреждение",
            "Возможное подключение к мошеннической точке доступа\n" + events[0].reason,
        )

    def set_status(self, text):
        self.status_label.setText(text)

    def closeEvent(self, event):
        self.stop_monitoring()
        super().closeEvent(event)

    def format_signal(self, value):
        if value is None:
            return "—"
        if value >= 0:
            return f"{max(0, min(100, value))}%"
        pct = int((value + 100) * 100 / 70)
        return f"{max(0, min(100, pct))}%"

    def auto_start(self):
        try:
            networks = self.worker.scanner.scan()
            connected = [ap for ap in networks if ap.is_connected]
            active = connected or networks
            events = self.engine.evaluate(active)
            self.update_table(active)
            if events:
                self.show_alerts(events)
            self.set_status("Автосканирование завершено")
        except Exception as exc:
            self.set_status(f"Ошибка автосканирования: {exc}")
        self.start_monitoring()


def run_app():
    cfg = default_config()
    engine = DetectionEngine(cfg)
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow(engine)
    app.aboutToQuit.connect(window.stop_monitoring)
    window.show()
    sys.exit(app.exec())
