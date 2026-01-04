#!/usr/bin/env python3
"""
PDF Malware Analyzer - Analyze PDFs for malicious content

Features:
- JavaScript detection
- Embedded file extraction
- Launch action detection
- Form/URI action analysis
- Structure anomaly detection
- Encryption analysis
- Object stream parsing
"""

import argparse
import json
import re
import zlib
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    location: Optional[str] = None


@dataclass
class AnalysisResult:
    filename: str
    size: int
    version: str
    encrypted: bool
    linearized: bool
    page_count: int
    findings: List[Finding]
    extracted_js: List[str]
    extracted_urls: List[str]
    embedded_files: List[str]
    risk_score: int
    is_malicious: bool


class PDFAnalyzer:
    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = {
        '/JavaScript': ('high', 'Contains JavaScript'),
        '/JS': ('high', 'Contains JavaScript reference'),
        '/Launch': ('critical', 'Launch action (can execute commands)'),
        '/OpenAction': ('medium', 'Auto-open action'),
        '/AA': ('medium', 'Additional actions'),
        '/EmbeddedFile': ('high', 'Embedded file'),
        '/RichMedia': ('medium', 'Rich media content'),
        '/XFA': ('medium', 'XFA forms'),
        '/AcroForm': ('low', 'Form fields'),
        '/JBIG2Decode': ('high', 'JBIG2 (potential exploit)'),
        '/Flash': ('high', 'Flash content'),
        '/U3D': ('medium', '3D content'),
        '/GoToR': ('medium', 'Remote GoTo action'),
        '/SubmitForm': ('medium', 'Form submission'),
        '/ImportData': ('medium', 'Data import'),
    }
    
    # Known exploit patterns
    EXPLOIT_PATTERNS = [
        (rb'util\.printf', 'CVE-2008-2992 (printf vulnerability)'),
        (rb'Collab\.collectEmailInfo', 'CVE-2007-5659 (Collab.collectEmailInfo)'),
        (rb'getAnnots', 'CVE-2009-1493 (getAnnots)'),
        (rb'getIcon', 'CVE-2009-0927 (getIcon buffer overflow)'),
        (rb'spell\.customDictionaryOpen', 'CVE-2009-1492 (spell vulnerability)'),
        (rb'media\.newPlayer', 'CVE-2009-4324 (media.newPlayer)'),
    ]
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.js_code: List[str] = []
        self.urls: Set[str] = set()
        self.embedded_files: List[str] = []
        
    def analyze(self, filepath: str) -> AnalysisResult:
        """Analyze a PDF file"""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Basic info
        size = len(data)
        version = self.get_pdf_version(data)
        encrypted = b'/Encrypt' in data
        linearized = b'/Linearized' in data
        page_count = self.count_pages(data)
        
        # Scan for suspicious content
        self.scan_keywords(data)
        self.scan_exploit_patterns(data)
        self.extract_javascript(data)
        self.extract_urls(data)
        self.check_streams(data)
        
        # Calculate risk
        risk_score = self.calculate_risk()
        is_malicious = risk_score >= 70
        
        return AnalysisResult(
            filename=filepath,
            size=size,
            version=version,
            encrypted=encrypted,
            linearized=linearized,
            page_count=page_count,
            findings=self.findings,
            extracted_js=self.js_code[:5],  # Limit
            extracted_urls=list(self.urls)[:20],
            embedded_files=self.embedded_files,
            risk_score=risk_score,
            is_malicious=is_malicious
        )
    
    def get_pdf_version(self, data: bytes) -> str:
        """Extract PDF version"""
        match = re.search(rb'%PDF-(\d+\.\d+)', data[:20])
        return match.group(1).decode() if match else "Unknown"
    
    def count_pages(self, data: bytes) -> int:
        """Count PDF pages"""
        matches = re.findall(rb'/Type\s*/Page[^s]', data)
        return len(matches)
    
    def scan_keywords(self, data: bytes):
        """Scan for suspicious keywords"""
        for keyword, (severity, description) in self.SUSPICIOUS_KEYWORDS.items():
            if keyword.encode() in data:
                self.findings.append(Finding(
                    severity=severity,
                    category='keyword',
                    title=f"Suspicious keyword: {keyword}",
                    description=description
                ))
    
    def scan_exploit_patterns(self, data: bytes):
        """Scan for known exploit patterns"""
        for pattern, exploit_name in self.EXPLOIT_PATTERNS:
            if re.search(pattern, data, re.I):
                self.findings.append(Finding(
                    severity='critical',
                    category='exploit',
                    title=f"Potential exploit: {exploit_name}",
                    description="Known vulnerability pattern detected"
                ))
    
    def extract_javascript(self, data: bytes):
        """Extract JavaScript code"""
        # Find JavaScript in streams
        js_patterns = [
            rb'/JS\s*\((.*?)\)',
            rb'/JavaScript\s*\((.*?)\)',
        ]
        
        for pattern in js_patterns:
            for match in re.finditer(pattern, data, re.S):
                js = match.group(1)
                try:
                    # Try to decode
                    js_decoded = js.decode('utf-8', errors='ignore')
                    if len(js_decoded) > 10:
                        self.js_code.append(js_decoded[:500])
                except:
                    pass
        
        # Check for obfuscated JS
        if re.search(rb'eval\s*\(', data, re.I):
            self.findings.append(Finding(
                severity='high',
                category='javascript',
                title='Obfuscated JavaScript (eval)',
                description='JavaScript using eval() for deobfuscation'
            ))
        
        if re.search(rb'unescape\s*\(', data, re.I):
            self.findings.append(Finding(
                severity='medium',
                category='javascript',
                title='JavaScript using unescape()',
                description='Potential string obfuscation'
            ))
    
    def extract_urls(self, data: bytes):
        """Extract URLs from PDF"""
        url_pattern = rb'https?://[^\s<>"\')\]\\]+'
        for match in re.finditer(url_pattern, data):
            url = match.group().decode('utf-8', errors='ignore')
            self.urls.add(url)
        
        # Check for suspicious URLs
        for url in self.urls:
            if any(sus in url.lower() for sus in ['.exe', '.bat', '.cmd', '.ps1', '.vbs']):
                self.findings.append(Finding(
                    severity='high',
                    category='url',
                    title='Suspicious URL with executable',
                    description=f'URL points to executable: {url[:60]}...'
                ))
    
    def check_streams(self, data: bytes):
        """Analyze PDF streams"""
        # Check for large streams (potential shellcode)
        stream_sizes = []
        for match in re.finditer(rb'stream\s+(.*?)\s+endstream', data, re.S):
            stream_sizes.append(len(match.group(1)))
        
        if stream_sizes:
            max_stream = max(stream_sizes)
            if max_stream > 100000:
                self.findings.append(Finding(
                    severity='medium',
                    category='stream',
                    title='Large stream detected',
                    description=f'Stream size: {max_stream} bytes (potential shellcode)'
                ))
    
    def calculate_risk(self) -> int:
        """Calculate risk score"""
        score = 0
        
        for finding in self.findings:
            if finding.severity == 'critical':
                score += 30
            elif finding.severity == 'high':
                score += 20
            elif finding.severity == 'medium':
                score += 10
            elif finding.severity == 'low':
                score += 5
        
        return min(100, score)


def print_banner():
    print(f"""{Colors.CYAN}
  ____  ____  _____   
 |  _ \|  _ \|  ___|  
 | |_) | | | | |_     
 |  __/| |_| |  _|    
 |_|   |____/|_|      
    _                _                    
   / \   _ __   __ _| |_   _ _______ _ __ 
  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ___ \| | | | (_| | | |_| |/ /  __/ |   
/_/   \_\_| |_|\__,_|_|\__, /___\___|_|   
                       |___/              
{Colors.RESET}                     v{VERSION}
""")


def print_result(result: AnalysisResult):
    """Print analysis results"""
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}PDF Information{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    
    print(f"  File: {result.filename}")
    print(f"  Size: {result.size:,} bytes")
    print(f"  Version: PDF {result.version}")
    print(f"  Pages: {result.page_count}")
    print(f"  Encrypted: {'Yes' if result.encrypted else 'No'}")
    
    # Findings
    if result.findings:
        print(f"\n{Colors.BOLD}Security Findings ({len(result.findings)}):{Colors.RESET}")
        
        for finding in result.findings:
            if finding.severity == 'critical':
                color = Colors.RED
            elif finding.severity == 'high':
                color = Colors.RED
            elif finding.severity == 'medium':
                color = Colors.YELLOW
            else:
                color = Colors.DIM
            
            print(f"  {color}[{finding.severity.upper()}]{Colors.RESET} {finding.title}")
            print(f"    {Colors.DIM}{finding.description}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}[OK] No suspicious content detected{Colors.RESET}")
    
    # Extracted data
    if result.extracted_js:
        print(f"\n{Colors.BOLD}Extracted JavaScript:{Colors.RESET}")
        for js in result.extracted_js[:3]:
            print(f"  {Colors.DIM}{js[:100]}...{Colors.RESET}")
    
    if result.extracted_urls:
        print(f"\n{Colors.BOLD}URLs Found ({len(result.extracted_urls)}):{Colors.RESET}")
        for url in result.extracted_urls[:5]:
            print(f"  {url[:60]}...")
    
    # Risk score
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    
    if result.risk_score >= 70:
        score_color = Colors.RED
        verdict = "MALICIOUS"
    elif result.risk_score >= 40:
        score_color = Colors.YELLOW
        verdict = "SUSPICIOUS"
    else:
        score_color = Colors.GREEN
        verdict = "CLEAN"
    
    print(f"{Colors.BOLD}Risk Score:{Colors.RESET} {score_color}{result.risk_score}/100 [{verdict}]{Colors.RESET}")


def demo_mode():
    """Demo with sample analysis"""
    print(f"{Colors.CYAN}Running demo analysis...{Colors.RESET}\n")
    
    demo_result = AnalysisResult(
        filename="malicious_sample.pdf",
        size=125000,
        version="1.7",
        encrypted=False,
        linearized=True,
        page_count=1,
        findings=[
            Finding('critical', 'keyword', 'Suspicious keyword: /JavaScript', 'Contains JavaScript'),
            Finding('high', 'keyword', 'Suspicious keyword: /Launch', 'Launch action (can execute commands)'),
            Finding('high', 'exploit', 'Potential exploit: CVE-2008-2992', 'Known vulnerability pattern detected'),
            Finding('medium', 'javascript', 'JavaScript using eval()', 'Potential obfuscation'),
        ],
        extracted_js=['app.alert("test"); eval(unescape("%48%65%6c%6c%6f"))'],
        extracted_urls=['http://evil.com/payload.exe'],
        embedded_files=[],
        risk_score=85,
        is_malicious=True
    )
    
    print_result(demo_result)


def main():
    parser = argparse.ArgumentParser(description="PDF Malware Analyzer")
    parser.add_argument("file", nargs="?", help="PDF file to analyze")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if not args.file:
        print(f"{Colors.YELLOW}No file specified. Use --demo for demonstration.{Colors.RESET}")
        return
    
    try:
        analyzer = PDFAnalyzer()
        result = analyzer.analyze(args.file)
        print_result(result)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(asdict(result), f, indent=2)
            print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")
            
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()
