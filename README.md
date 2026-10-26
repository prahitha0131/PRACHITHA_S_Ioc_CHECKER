# Simple Local IoC Checker


A beginner-friendly cybersecurity project that identifies the format of an IP address, domain, or file hash and checks it against a tiny local sample dataset. It demonstrates basic indicator-of-compromise (IoC) handling without contacting external services.

## Important data note

The included records are teaching examples only. The IPs are reserved for documentation and the domain uses the reserved `.test` suffix. A result of `UNKNOWN` means there was no match in this tiny local list; it does not mean an indicator is safe. This project is not a live threat feed or a security verdict system.

## Requirements

- Python 3.9 or later
- No third-party packages (standard library only)

## Run

```bash
python ioc_checker.py 198.51.100.23
python ioc_checker.py example.test
python ioc_checker.py 8.8.8.8
```

The program prints the detected format, local match status, risk label, and a short note. `8.8.8.8` will be reported as not present in the example dataset with risk `UNKNOWN`.

## How it works

1. `identify_type` checks whether input is a valid IP address, a 32/40/64-character hexadecimal hash, or a basic domain name.
2. `check_indicator` normalizes the input and performs an exact lookup in `SAMPLE_INDICATORS`.
3. If there is no match, it returns `UNKNOWN` rather than guessing a threat level.

## Files

- `ioc_checker.py` — project code
- `requirements.txt` — dependency list
- `README.md` — setup and use
- `*_ProjectReport.docx` — project report

## Dataset

There is no external dataset. A small synthetic teaching dataset is embedded in the Python file. The sample IP ranges and `.test` domain are reserved for examples and should not be used as real threat intelligence.

## Ethical use

Use this program for learning and authorized defensive work. Do not use its output alone to block, allow, or investigate real systems. For real analysis, use reputable current sources and follow your institution's and service providers' terms.
