# 📁 File Tracker

Aplikasi Python untuk melacak dan memonitor file yang dibuka di sistem Windows.

## ✨ Fitur

- **Scan File Terbuka**: Melihat semua file yang sedang dibuka oleh proses di sistem
- **Filter by Process**: Filter berdasarkan nama aplikasi (e.g., notepad, chrome)
- **Filter by Extension**: Filter berdasarkan ekstensi file (.txt, .py, .docx, dll)
- **Real-time Monitoring**: Monitor aktivitas file secara real-time di direktori tertentu

## 📖 Cara Penggunaan

### 1. Scan File yang Sedang Dibuka

```bash
# Scan semua file yang sedang dibuka
python file_tracker.py scan

# Scan file dengan ekstensi tertentu
python file_tracker.py scan -e .txt .py .docx

# Kombinasi filter
python file_tracker.py scan -p vscode -e .py .js

# Export hasil ke JSON
python file_tracker.py scan -o hasil_scan.json
```

### 2. Lihat Riwayat Aktivitas

```bash
# Tampilkan 20 aktivitas terbaru
python file_tracker.py history

# Tampilkan N aktivitas terbaru
python file_tracker.py history -n 50
```

## 📊 Contoh Output

### Scan Output
```
================================================================================
📊 FILE YANG SEDANG DIBUKA
================================================================================

🔹 Process: Code.exe (15 file)
------------------------------------------------------------
     1. C:\Projects\myapp\main.py
     2. C:\Projects\myapp\utils.py
     3. C:\Projects\myapp\config.json

## 📋 API Reference

### Class: `FileTracker`

#### Constructor Parameters:
- `watch_directories`: List direktori untuk dimonitor
- `extensions`: List ekstensi file untuk difilter
- `log_file`: Path file log (default: "file_tracker.log")
- `activity_file`: Path file aktivitas JSON (default: "file_activities.json")

#### Methods:
- `get_open_files_by_process(process_name)` - Dapatkan file yang dibuka oleh proses
- `start_monitoring(directories)` - Mulai monitoring real-time
- `stop_monitoring()` - Hentikan monitoring


## ⚠️ Catatan Penting

1. **Hak Akses Admin**: Beberapa proses sistem mungkin memerlukan hak akses administrator untuk di-scan
2. **Performa**: Scanning semua proses bisa memakan waktu jika banyak aplikasi yang berjalan
3. **Windows Only**: Tool ini dioptimalkan untuk Windows, beberapa fitur mungkin berbeda di OS lain

## 📄 License

MIT License - Bebas digunakan dan dimodifikasi.

