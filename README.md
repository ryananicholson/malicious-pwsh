# malicious-pwsh

Finding evil in PowerShell logs. This script defines evil as Event Data that scores less than a 5.0 using Mark Baggett's freq.py (also included in this repo).

More info on freq.py can be found [here](https://github.com/MarkBaggett/freq).

## Requirements

- Install appropriate python3 requirements

    ```
    pip3 install -r requirements.txt
    ```
    
- A Microsoft-Windows-PowerShell/Operational .evtx file to audit

## Usage

```
python3 malicious-pwsh.py <file.evtx>
```

