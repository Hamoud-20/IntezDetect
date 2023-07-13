# IntezDetect
I created a Python tool that uses the Intezer Analyze API to scan files and directories for malware. The tool is easy to use and provides a command line interface for specifying the file or directory to scan. It uses an API key for authentication and supports parallel scanning, progress tracking, and color-coded output for easier analysis.

# Features:
- Scan files and directories for malware using the Intezer Analyze API
- Command line interface for easy usage
- API key authentication for security
- Parallel scanning for faster results
- Progress tracking using the tqdm library
- Results displayed in a pretty table format
- Color-coded output to highlight potential threats
# Installation
Step 1:
```
git clone https://github.com/Hamoud-20/IntezDetect.git
```
Step 2:
```
pip install -r requirements.txt
```
Step 3:
Set up your Intezer Analyze API key:
```
API_KEY = "YOUR_API_KEY"
```
# Usage
```
 python IntezDetect.py -h  
```

<img width="770" alt="image" src="https://github.com/Hamoud-20/IntezDetect/assets/137123444/18c6e509-cf20-4391-bc18-9881c62c49b2">

```console
options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The file to scan.
  -d DIRECTORY, --directory DIRECTORY
                        The directory to scan.

```
# Scan FILE
```
 python IntezDetect.py -f <FILE>
```
<img width="795" alt="image" src="https://github.com/Hamoud-20/IntezDetect/assets/137123444/b4307724-9047-434c-8e9e-8248e7ea284a">

# Scan DIRECTORY
```
 python IntezDetect.py -d <path>
```
<img width="1437" alt="image" src="https://github.com/Hamoud-20/IntezDetect/assets/137123444/99e25601-287a-4a40-8450-412f6af96453">

<img width="749" alt="image" src="https://github.com/Hamoud-20/IntezDetect/assets/137123444/992356a3-f991-4866-8d78-665d87c9e02c">

# Summary

This tool will help you analyze all files with all kinds of extensions and also tell you a detailed analysis.

Happy threat hunting!
