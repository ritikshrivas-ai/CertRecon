# 🛡️CertRecon: Advanced Enumeration & Reconnaissance Tool

## 🎯 Overview
CertRecon is a fast and efficient subdomain enumeration and reconnaissance tool built to simplify the recon process by using certificate transparency logs and multiple enumeration techniques. It filters live subdomains and generates reports for further analysis.

---

## ⚡ Features
- **Subdomain Enumeration:** Utilizes sources like Cert.sh and other fast platforms.
- **Live Host Verification:** Confirms active subdomains.
- **Subdomain Takeover Check:** Detects possible subdomain takeover vulnerabilities.
- **Port & Vulnerability Scanning:** Identifies open ports and basic vulnerabilities.
- **Stylish CLI Interface:** Dynamic ASCII banners, colorful progress bars, and engaging UI.

---

## 🖥️ Installation
```bash
git clone https://github.com/ritikshrivas-ai/CertRecon.git
cd CertRecon
pip install -r requirements.txt
```

---

## 🚀 Usage
```bash
python certrecon.py -d <target-domain.com>
```
- `-d` : Target domain for scanning
- `-o` : Save results to a specified file

---

## 📜 Examples
```bash
python certrecon.py -d example.com -o results.txt
```

---

## 📝 Requirements
- Python 3.x
- Kali Linux / Parrot OS
- Required Libraries (installed via `requirements.txt`)

---

## 🧠 Contribution Guidelines
- Fork the repository.
- Create a new branch.
- Submit a pull request with a detailed description.

---

## 📧 Contact
- GitHub: [Ritik Shrivas](https://github.com/ritikshrivas-ai)
- Email: ritikshrivas.ai@gmail.com

---

## ⚖️ License
This project is licensed under the **MIT License**.

---

## 🌟 Acknowledgments
Special thanks to the cybersecurity community for their support and inspiration.
