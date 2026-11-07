# SOC Analyst Portfolio

Hands-on labs and investigations in security operations (SOC) and blue team work. Each write-up documents the data, the method, the evidence and the conclusion, including what the evidence does not prove.

## Labs

| # | Lab | Platform | Tools | Topics |
|---|---|---|---|---|
| 1 | [Web server compromise investigation](thm-splunk-basics-web-attack/) | TryHackMe | Splunk | Log analysis, SQL injection, webshell and RCE, C2 detection, MITRE ATT&CK |
| 2 | [Exploring SPL](thm-splunk-exploring-spl/) | TryHackMe | Splunk | SPL commands, data enrichment, statistical anomaly detection (z-score) |

## Resources

| File | Description |
|---|---|
| [Splunk Cheat Sheet](cheatsheets/Splunk_Cheat_Sheet.pdf) | SPL quick reference and investigation templates |

## Repository structure

```
.
├── README.md
├── cheatsheets/                      reference sheets
├── thm-splunk-basics-web-attack/     one folder per lab
│   ├── README.md                     write-up
│   └── images/                       screenshots
└── thm-splunk-exploring-spl/
```

Lab folders are named `<platform>-<topic>-<scenario>` (for example `thm` for TryHackMe, `htb` for Hack The Box).

## Skills demonstrated

- Log analysis and threat hunting with Splunk (SPL)
- Attack chain reconstruction and correlation across log sources
- Data enrichment (`lookup`, `iplocation`, `eval`) and statistical anomaly detection
- MITRE ATT&CK mapping and incident reporting

## Contact

[LinkedIn](https://www.linkedin.com/in/ahmed-khader7) | [GitHub](https://github.com/ahmed121237)
