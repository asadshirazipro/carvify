# Carvify - Ultimate Forensic Tool

![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![GUI](https://img.shields.io/badge/GUI-PyQt6-41CD52?logo=qt&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success)

**Carvify** is a Windows forensic recovery tool built with Python and PyQt6. It scans physical drives and disk images and carves **14 file types** out of deleted and unallocated data using signature-based analysis.

Website: [carvify.shirazi.pk](https://carvify.shirazi.pk)
Release date: 14/08/2026

---

## Features

- **Signature-based file carving** - recovers files by header/footer signatures, without relying on the file system
- **Drives and disk images** - scan live drives or raw image files
- **Multithreaded scanning** - parallel workers keep the UI responsive and speed up large scans
- **Live previews** - view recovered files as they are found
- **Hex-level inspector** - examine raw bytes of any carved result
- **Sector-aligned export** - export carved data aligned to disk sectors for forensic accuracy
- **Modern PyQt6 interface** - clean, easy-to-use desktop GUI

## Supported File Types

Carvify currently carves 14 file types:

| Category   | Types                  |
|------------|------------------------|
| Images     | JPG, PNG, GIF, BMP     |
| Documents  | PDF, DOCX, XLSX, PPTX  |
| Archives   | ZIP, RAR, 7Z           |
| Media      | MP3, MP4, AVI          |

## Installation

### Requirements

- Windows 10 / 11
- Python 3.10 or newer
- Administrator privileges (needed to read raw physical drives)


1. Run Carvify **as Administrator**.
2. Select a **drive** or open a **disk image**.
3. Choose the file types you want to recover.
4. Click **Start Scan** and watch results appear with live previews.
5. Inspect any result in the **hex viewer**.
6. **Export** the recovered files to a separate, safe destination drive.

> **Tip:** Always export recovered files to a different drive than the one being scanned, so you never overwrite the data you are trying to recover.

## How It Works

1. **Read** - raw sectors are read from the drive or image in chunks.
2. **Match** - each chunk is scanned for known file header signatures (and footers where applicable).
3. **Carve** - matched regions are extracted into candidate files.
4. **Review** - results are previewed and can be inspected at hex level.
5. **Export** - selected files are written out with sector-aligned offsets.

## Project Structure

```
carvify/
├── main.py            # Application entry point
├── requirements.txt   # Python dependencies
├── ui/                # PyQt6 interface
├── core/              # Scanner, signatures, carving engine
└── README.md
```


## Legal and Ethical Use

Carvify is intended for **digital forensics, data recovery, education, and authorized investigations only**. Only scan drives and images you own or have explicit permission to examine. The author is not responsible for misuse.



## Author

Developed by **Shirazi** - [carvify.shirazi.pk](https://carvify.shirazi.pk)
