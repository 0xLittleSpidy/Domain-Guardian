# TypoScout 

## Overview

TypoScout is a robust and asynchronous typosquatting domain reconnaissance tool. It is designed to generate typo variations of a given domain, verify their availability, resolve IP addresses, and export results into a detailed CSV report. This is especially useful for red teamers conducting phishing or brand protection assessments.

### Offensive Techniques Simulated

This tool replicates the same methodologies that malicious actors use to generate typosquats:

#### 1. Character Manipulation Algorithms
```
Original Domain: example.com

Omission Attack:     exmple.com, exampl.com
Repetition Attack:   exxample.com, examplle.com
Substitution Attack: wxample.com, rxample.com
Transposition:       exmaple.com, examlpe.com
Insertion Attack:    exaample.com, examplle.com
```

#### 2. TLD Substitution Strategy
Attackers commonly register domains across multiple TLDs to maximize their attack surface:
- `.com` → `.net`, `.org`, `.info`, `.biz`
- Country-code variations: `.co`, `.io`, `.me`, `.tv`

#### 3. Keyboard Layout Exploitation
The tool leverages QWERTY keyboard proximity to generate realistic typos:
- `a` → `q`, `w`, `s`, `z`
- `m` → `n`, `k`, `j`

## Installation & Setup

### Prerequisites
```bash
pip install aiohttp dnspython
```

### Quick Start
```bash
# Basic domain analysis
python typoscout.py -d target-brand.com

# Bulk analysis from file
python typoscout.py -df target_domains.txt -o intelligence_report.csv

# High-speed reconnaissance mode
python typoscout.py -d example.com -r 20 --debug
```

## Command Line Interface

```
typoscout - Typosquatting Domain Reconnaissance

optional arguments:
  -h, --help            Show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Single domain target for analysis
  -df DOMAIN_FILE, --domain-file DOMAIN_FILE
                        File containing multiple domain targets
  -o OUTPUT, --output OUTPUT
                        Output CSV file for intelligence gathering
  -r REQUESTS_PER_SECOND, --requests-per-second REQUESTS_PER_SECOND
                        Request rate configuration (default: 10 req/sec)
  -de, --debug          Enable verbose reconnaissance mode
```

## Operational Modes

### 1. Reconnaissance Mode (`--debug`)
Provides real-time domain status as discovered:
```
Domain,Status,IP_Addresses
exampl.com,Available,
exmaple.com,Registered,192.168.1.100
examlpe.com,Available,
```

### 2. Stealth Mode (Default)
Displays progress indicators without revealing individual results until completion.

### 3. Intelligence Export Mode (`-o`)
Generates comprehensive CSV reports containing:
- Domain variations identified
- Registration status
- IP address assignments
- Nameserver configurations
- Potential registrar information

## Threat Modeling Applications

### For Red Team Operations
- **Domain Generation**: Understanding how adversaries create convincing typosquats
- **Infrastructure Planning**: Identifying available domains for controlled exercises
- **Attack Surface Mapping**: Comprehensive enumeration of potential vectors

### For Blue Team Defense
- **Brand Monitoring**: Proactive identification of malicious registrations
- **Threat Intelligence**: Understanding attacker domain selection patterns
- **Preventive Registration**: Defensive domain purchases to reduce attack surface

### For Penetration Testing
- **Social Engineering Prep**: Realistic domain alternatives for phishing simulations
- **Client Education**: Demonstrating vulnerability to typosquatting attacks
- **Security Awareness**: Showing real-world domain variations that could fool users

## Performance Metrics

The tool provides comprehensive performance analytics:

```
Execution time: 45.23 seconds
Domains checked: 2,847
Average rate: 62.97 domains/second
```

### Optimization Features
- **Concurrent Processing**: Async implementation for maximum throughput
- **DNS Caching**: Intelligent result caching to avoid redundant queries
- **Error Handling**: Robust exception management for unreliable networks
- **Resource Management**: Automatic connection pooling and cleanup

## Output Analysis

### CSV Report Structure
```csv
domain,status,ip_addresses,nameservers,registrar
exampl.com,Available,,,
exmaple.com,Registered,203.0.113.10,ns1.example.net,GoDaddy
wxample.com,Registered,198.51.100.5,dns1.registrar.com,Namecheap
```

### Status Categories
- **Available**: Domain not registered - potential defensive registration target
- **Registered**: Active domain - requires further investigation
- **Error**: DNS resolution issues - may indicate blocking or rate limiting


## Contributing
Contributions are welcome! If you'd like to contribute to this project, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

---

# **Ethical Use Only**  

This tool is intended for **legal and authorized security assessments only**. By using this software, you agree to comply with all applicable laws and regulations.  

## **Legal Disclaimer**  
The developers of this tool are **not responsible** for any misuse or illegal activities conducted with it.

**Use responsibly and ethically.** Always obtain **written permission** before scanning third-party systems.  

---  
*By using this tool, you acknowledge that you understand and agree to these terms.*
