# Footprint Pro

Footprint Pro is a Kali-friendly email OSINT reporter. It runs without a virtual environment:

```bash
cd Footprint-Pro
bash scripts/install_kali.sh
python3 footprint
```

It asks for a target email, scans public passive sources, runs Holehe and Sherlock if installed, then saves:

```text
output/target@example.com.html
```

## Output Sections

- Profile summary
- Names
- Usernames
- Locations
- Dates
- Links
- Profile pictures
- Accounts and platforms
- Domain intelligence
- Holehe output
- Sherlock output

## Optional Tools

```bash
sudo apt install -y sherlock
sudo apt install -y pipx
pipx install holehe
```
