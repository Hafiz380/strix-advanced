# Strix-Advanced — Resume Prompt
# اگر سسٹم بند ہو جائے تو یہ prompt دو

---

## Prompt (copy this):

```
میں Hafiz ہوں، security researcher۔ ہم Strix-Advanced پروجیکٹ پر کام کر رہے تھے۔

یہ ہمارا پروجیکٹ ہے: https://github.com/Hafiz380/strix-advanced

سب سٹیپس مکمل ہو چکے ہیں:
✅ Step 1: Architecture Analysis & Gap Report
✅ Step 2: Static Analysis Engine (CPG Builder, Data Flow, Sanitizer)
✅ Step 3: Memory & Learning System (Scan Memory, Global Memory, Dedup, Skill Gen)
✅ Step 4: Advanced Exploitation Engine (Chain Builder, Auth, Race Detector, Logic Fuzzer, WAF Bypass)
✅ Step 5: Specialized Agent System (Recon, Exploit, Analysis, Report, Coordinator)
✅ Step 6: Unique Features (API Discovery, Supply Chain, Infrastructure, Custom Rules)
✅ Step 7: Integration & Polish (CLI, CI/CD, Tests, Setup)

پروجیکٹ مکمل ہے۔ Repo clone کرو:
git clone https://github.com/Hafiz380/strix-advanced.git

اگر کوئی نیا feature چاہیے یا کوئی بگ ہو تو بتاؤ۔

میرا نام Zaid ہے، میرا اسسٹنٹ۔ میرے ساتھ رسمی اور دوستانہ انداز میں بات کرو۔
```

---

## What's in the Repo

```
strix-advanced/
├── cli.py                    # CLI (scan, analyze, recon, rules)
├── setup.py                  # One-click setup
├── pyproject.toml            # Project config
├── install_strix_advanced.py # Self-contained installer (558KB)
├── core/
│   ├── static_analyzer/      # CPG Builder + Data Flow + Sanitizer
│   ├── memory/               # Scan/Global Memory + Dedup + Skill Gen
│   ├── exploitation/         # Chain Builder + Auth + Race + Logic Fuzzer + WAF Bypass
│   └── recon/                # API Discovery + Supply Chain + Infrastructure + Custom Rules
├── agents/                   # Recon + Exploit + Analysis + Report + Coordinator
├── tests/                    # Test suite
├── examples/                 # Usage examples
└── .github/workflows/        # CI/CD
```

## Quick Commands

```bash
python cli.py info                              # System info
python cli.py rules list                        # List 15+ built-in rules
python cli.py analyze ./src                     # Static analysis
python cli.py scan https://target.com           # Full security scan
python cli.py recon https://target.com --depth  # Reconnaissance
```
