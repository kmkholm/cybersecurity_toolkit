# -*- coding: utf-8 -*-
"""
Integrated Cybersecurity Toolkit v5.0
Created on December 2025

Author: Dr. Mohammed Tawfik
Email: kmkhol01@gmail.com
License: Educational Use Only



⚠️  WARNING: EDUCATIONAL USE ONLY - Unauthorized use is illegal!
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import hashlib
import threading
import itertools
import re
import time
import json
import socket
import random
import string
import platform
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Try to import shodan
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# Additional imports for v6.0 features
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import dns.resolver  
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

import ssl
import requests


# --- CONFIGURATION ---
MAX_WORDLIST_SIZE = 2000000
DEFAULT_CPU_THREADS = 8

class ApplicationSettings:
    """Global settings manager"""
    def __init__(self):
        self.cpu_workers = DEFAULT_CPU_THREADS
        self.gpu_enabled = False
        self.use_gpu = False
        self.max_brute_length = 8
        self.year_range_start = 2023
        self.year_range_end = 2026
        self.attack_paused = False
        self.attack_stopped = False
        self.use_common_combinations = True
        self.combo_min_length = 1
        self.combo_max_length = 8
        self.combo_charset_type = "letters+numbers"
        self.online_timeout = 5
        self.online_delay = 0.1
        self.online_threads = 4
        self.loaded_wordlist = None
        self.unlimited_mode = False
        self.max_attempts = 100000
        self.chatgpt_api_key = ""
        self.claude_api_key = ""
        self.ai_provider = "chatgpt"


SETTINGS = ApplicationSettings()

# Hash signatures
HASH_SIGNATURES = {
    'NetNTLMv2': (None, r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$', 
                  'Windows network authentication. Requires specialized cracking.', 1),
    'NetNTLMv1': (None, r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$',
                  'Legacy Windows network auth. Dictionary attack recommended.', 2),
    'SHA512': (128, r'^[a-fA-F0-9]{128}$', 'Medium speed, 128 hex. Dictionary highly preferred.', 3),
    'SHA256': (64, r'^[a-fA-F0-9]{64}$', 'Medium speed, 64 hex. Dictionary highly preferred.', 4),
    'SHA1': (40, r'^[a-fA-F0-9]{40}$', 'Fast, 40 hex. Dictionary/Brute-force viable.', 5),
    'MD5': (32, r'^[a-fA-F0-9]{32}$', 'Fast, 32 hex. Dictionary/Brute-force viable.', 6),
    'NTLM': (32, r'^[a-fA-F0-9]{32}$', 'Windows NTLM (MD4). Dictionary/Brute-force viable.', 7),
    'MySQL_OLD': (16, r'^[a-fA-F0-9]{16}$', 'Very weak. High-speed dictionary attack.', 8),
    'MD5(WordPress)': (34, r'^\$P\$[A-Za-z0-9\./]{31}$', 'Salted MD5. Targeted dictionary.', 9),
    'MD5(Joomla)': (49, r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16}$', 'Salted MD5 + salt. Dictionary.', 10),
    'UNIX_BCRYPT': (60, r'^\$2[abyx]\$.{56}$', 'Slow. Targeted dictionary + GPU recommended.', 11),
    'UNIX_ARGON2': (None, r'^\$argon2[id]?\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+$', 'Very slow. GPU required.', 12),
}

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "12345", "qwerty", "abc123", "111111",
    "password123", "admin", "admin123", "root", "toor", "pass", "test",
    "welcome", "monkey", "dragon", "master", "letmein", "login", "princess",
    "1234", "1234567", "123456789", "password1", "qwerty123", "000000"
]

COMMON_APPENDS = ["123", "!", "@", "#", "$", "1", "12", "123!", "2024", "2025", "2026", "01", "!@#"]
COMMON_PREFIXES = ["!", "@", "#", "$", "admin", "user", "test"]

def identify_hash(hash_string, context_hints=None):
    """Hash identification"""
    hash_length = len(hash_string)
    possible_matches = []
    
    for name, (length, pattern, recommendation, priority) in HASH_SIGNATURES.items():
        if re.match(pattern, hash_string):
            if length is None or hash_length == length:
                possible_matches.append((name, recommendation, priority))
    
    if context_hints and len(possible_matches) > 1:
        source = context_hints.get('source', '').lower()
        if source == 'windows':
            for match in possible_matches:
                if 'NTLM' in match[0]:
                    return match[0], match[1]
    
    if possible_matches:
        possible_matches.sort(key=lambda x: x[2])
        return possible_matches[0][0], possible_matches[0][1]
    
    if hash_string.count('$') >= 2 or hash_string.count(':') >= 1:
        return 'Custom-Salted', "Custom salted format. Full context required."
    
    if hash_length > 10 and re.match(r'^[a-zA-Z0-9+/=]+$', hash_string):
        return 'Unknown-Complex-Base64', "Base64-encoded. Dictionary recommended."
    
    return 'Unknown-Brute', "Hash structure not recognized. Try dictionary/brute-force."

# --- WORDLIST GENERATION ---

def apply_leetspeak(word):
    """Leetspeak mutations"""
    leetspeak_map = {
        'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 
        'o': ['0'], 's': ['$', '5'], 't': ['7'], 
        'l': ['1'], 'g': ['9'], 'b': ['8']
    }
    mutations = {word}
    
    for char, replacements in leetspeak_map.items():
        if char in word.lower():
            for replacement in replacements:
                mutations.add(word.replace(char, replacement))
                mutations.add(word.replace(char.upper(), replacement))
    
    return mutations

def generate_charset_from_type(charset_type):
    """Generate charset from type"""
    if charset_type == "letters":
        return string.ascii_lowercase
    elif charset_type == "LETTERS":
        return string.ascii_uppercase
    elif charset_type == "numbers":
        return string.digits
    elif charset_type == "letters+numbers":
        return string.ascii_lowercase + string.digits
    elif charset_type == "LETTERS+numbers":
        return string.ascii_uppercase + string.digits
    elif charset_type == "Letters+Numbers":
        return string.ascii_letters + string.digits
    elif charset_type == "all":
        return string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    else:
        return string.ascii_lowercase + string.digits

def generate_common_combinations():
    """Generate common password combinations"""
    wordlist = set(COMMON_PASSWORDS)
    
    for base in list(COMMON_PASSWORDS[:15]):
        for append in COMMON_APPENDS:
            wordlist.add(f"{base}{append}")
        
        for prefix in COMMON_PREFIXES:
            wordlist.add(f"{prefix}{base}")
        
        wordlist.add(base.upper())
        wordlist.add(base.capitalize())
        wordlist.add(base[::-1])
    
    return list(wordlist)

def generate_targeted_wordlist(keywords_csv, year_range=(2023, 2026), use_combinations=True):
    """Generate targeted wordlist"""
    keywords = set(kw.strip() for kw in keywords_csv.split(',') if kw.strip())
    
    if not keywords and use_combinations:
        return generate_common_combinations()
    
    wordlist = set(keywords)
    
    for keyword in list(keywords):
        wordlist.add(keyword.upper())
        wordlist.add(keyword.capitalize())
        wordlist.add(keyword[::-1])
        
        wordlist.update(apply_leetspeak(keyword))
        
        for append in COMMON_APPENDS:
            wordlist.add(f"{keyword}{append}")
        
        for prefix in COMMON_PREFIXES:
            wordlist.add(f"{prefix}{keyword}")
        
        for year in range(year_range[0], year_range[1] + 1):
            wordlist.add(f"{keyword}{year}")
    
    return list(wordlist)

def load_wordlist_from_file(filepath):
    """Load wordlist"""
    try:
        passwords = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if password:
                    passwords.append(password)
                if len(passwords) >= MAX_WORDLIST_SIZE:
                    break
        return passwords
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load wordlist: {str(e)}")
        return []

# --- HASH CALCULATION ---

def calculate_hash(password, hash_type):
    """Calculate hash"""
    if hash_type == 'MD5':
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == 'SHA1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == 'SHA256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == 'SHA512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_type == 'NTLM':
        import codecs
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    else:
        return hashlib.md5(password.encode()).hexdigest()

# --- ATTACK FUNCTIONS ---

def perform_dictionary_attack(target_hash, hash_type, wordlist, log_callback, settings):
    """Dictionary attack with CPU/GPU"""
    start_time = time.time()
    attempts = 0
    found = None
    
    log_callback(f"[DICT] Starting with {len(wordlist):,} candidates")
    log_callback(f"[MODE] {'GPU' if settings.use_gpu else 'CPU'} ({settings.cpu_workers} workers)")
    
    def check_batch(batch):
        nonlocal attempts, found
        for password in batch:
            if settings.attack_stopped:
                return None
            
            attempts += 1
            calculated = calculate_hash(password, hash_type)
            
            if calculated == target_hash:
                return password
            
            if attempts % 10000 == 0:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                log_callback(f"[PROGRESS] {attempts:,} tries | {speed:.0f} h/s")
        
        return None
    
    batch_size = 1000
    with ThreadPoolExecutor(max_workers=settings.cpu_workers) as executor:
        futures = []
        for i in range(0, len(wordlist), batch_size):
            if settings.attack_stopped:
                break
            batch = wordlist[i:i+batch_size]
            futures.append(executor.submit(check_batch, batch))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                found = result
                break
    
    duration = time.time() - start_time
    
    if found:
        log_callback(f"[SUCCESS] Password: {found}")
        log_callback(f"[STATS] {attempts:,} attempts in {duration:.2f}s ({attempts/duration:.0f} h/s)")
    else:
        log_callback(f"[FAILED] Dictionary exhausted ({attempts:,} attempts)")
    
    return found, duration

def perform_brute_force_unlimited(target_hash, hash_type, max_length, charset, log_callback, settings):
    """Unlimited brute force with random generation"""
    start_time = time.time()
    attempts = 0
    found = None
    
    log_callback(f"[BRUTE] Starting unlimited random mode")
    log_callback(f"[CHARSET] {charset}")
    log_callback(f"[LENGTH] 1-{max_length}")
    
    while not settings.attack_stopped:
        length = random.randint(1, max_length)
        password = ''.join(random.choice(charset) for _ in range(length))
        
        attempts += 1
        calculated = calculate_hash(password, hash_type)
        
        if calculated == target_hash:
            found = password
            break
        
        if attempts % 10000 == 0:
            elapsed = time.time() - start_time
            speed = attempts / elapsed if elapsed > 0 else 0
            log_callback(f"[PROGRESS] {attempts:,} tries | {speed:.0f} h/s | Testing: {password}")
        
        if not settings.unlimited_mode and attempts >= settings.max_attempts:
            log_callback(f"[LIMIT] Max attempts reached ({settings.max_attempts:,})")
            break
    
    duration = time.time() - start_time
    
    if found:
        log_callback(f"[SUCCESS] Password: {found}")
        log_callback(f"[STATS] {attempts:,} attempts in {duration:.2f}s ({attempts/duration:.0f} h/s)")
    else:
        log_callback(f"[FAILED] Stopped after {attempts:,} attempts")
    
    return found, duration

# --- ONLINE ATTACK ---

class OnlineAttacker:
    """Online protocol attack"""
    def __init__(self, host, port, protocol, log_callback, settings):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.log = log_callback
        self.settings = settings
    
    def attack(self, usernames, passwords):
        start_time = time.time()
        attempts = 0
        found = None
        
        self.log(f"[ONLINE] Testing {len(usernames)} users × {len(passwords)} passwords")
        
        for username in usernames:
            if self.settings.attack_stopped:
                break
            
            for password in passwords:
                if self.settings.attack_stopped:
                    break
                
                attempts += 1
                
                if self.protocol == 'SSH':
                    result = self._test_ssh(username, password)
                elif self.protocol == 'FTP':
                    result = self._test_ftp(username, password)
                elif self.protocol == 'Telnet':
                    result = self._test_telnet(username, password)
                else:
                    result = False
                
                if result:
                    found = (username, password)
                    break
                
                time.sleep(self.settings.online_delay)
                
                if attempts % 10 == 0:
                    self.log(f"[PROGRESS] {attempts} attempts | Testing: {username}:{password}")
            
            if found:
                break
        
        duration = time.time() - start_time
        
        if found:
            self.log(f"[SUCCESS] Found: {found[0]}:{found[1]}")
        else:
            self.log(f"[FAILED] No valid credentials found")
        
        return found, duration
    
    def _test_ssh(self, username, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.settings.online_timeout)
            sock.connect((self.host, self.port))
            sock.close()
            return False
        except:
            return False
    
    def _test_ftp(self, username, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.settings.online_timeout)
            sock.connect((self.host, self.port))
            sock.close()
            return False
        except:
            return False
    
    def _test_telnet(self, username, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.settings.online_timeout)
            sock.connect((self.host, self.port))
            sock.close()
            return False
        except:
            return False

# --- NETWORK UTILITIES ---

class NetworkTools:
    """Network diagnostic tools"""
    
    @staticmethod
    def ping(host, count=4, timeout=2):
        """Execute ping command"""
        results = {
            'host': host,
            'sent': count,
            'received': 0,
            'lost': 0,
            'loss_percent': 0,
            'min_time': 0,
            'max_time': 0,
            'avg_time': 0,
            'success': False,
            'output': '',
            'error': ''
        }
        
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, str(count), host]
            
            if platform.system().lower() != 'windows':
                command.extend(['-W', str(timeout)])
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output, error = process.communicate(timeout=timeout * count + 5)
            
            results['output'] = output
            results['error'] = error
            
            if process.returncode == 0:
                results['success'] = True
                
                # Parse output for statistics
                if platform.system().lower() == 'windows':
                    # Windows parsing
                    if 'Received = ' in output:
                        match = re.search(r'Received = (\d+)', output)
                        if match:
                            results['received'] = int(match.group(1))
                    
                    if 'Minimum = ' in output:
                        match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
                        if match:
                            results['min_time'] = int(match.group(1))
                            results['max_time'] = int(match.group(2))
                            results['avg_time'] = int(match.group(3))
                else:
                    # Linux/Unix parsing
                    if 'received' in output:
                        match = re.search(r'(\d+) received', output)
                        if match:
                            results['received'] = int(match.group(1))
                    
                    if 'min/avg/max' in output or 'rtt' in output:
                        match = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)', output)
                        if match:
                            results['min_time'] = float(match.group(1))
                            results['avg_time'] = float(match.group(2))
                            results['max_time'] = float(match.group(3))
                
                results['lost'] = results['sent'] - results['received']
                if results['sent'] > 0:
                    results['loss_percent'] = (results['lost'] / results['sent']) * 100
            
        except subprocess.TimeoutExpired:
            results['error'] = 'Ping timeout expired'
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    @staticmethod
    def resolve_hostname(host):
        """Resolve hostname to IP"""
        try:
            ip = socket.gethostbyname(host)
            return {'success': True, 'ip': ip, 'hostname': host}
        except socket.gaierror as e:
            return {'success': False, 'error': str(e), 'hostname': host}

# --- SHODAN INTEGRATION ---

class ShodanScanner:
    """Shodan API integration for reconnaissance"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.api = None
        
        if SHODAN_AVAILABLE:
            try:
                self.api = shodan.Shodan(api_key)
            except Exception as e:
                raise Exception(f"Shodan initialization failed: {str(e)}")
        else:
            raise Exception("Shodan library not installed. Install with: pip install shodan")
    
    def search(self, query, limit=10):
        """Search Shodan"""
        try:
            results = self.api.search(query, limit=limit)
            return {
                'success': True,
                'total': results['total'],
                'matches': results['matches']
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def host_info(self, ip):
        """Get host information"""
        try:
            host = self.api.host(ip)
            return {
                'success': True,
                'ip': host['ip_str'],
                'organization': host.get('org', 'N/A'),
                'operating_system': host.get('os', 'N/A'),
                'ports': host.get('ports', []),
                'hostnames': host.get('hostnames', []),
                'country': host.get('country_name', 'N/A'),
                'city': host.get('city', 'N/A'),
                'isp': host.get('isp', 'N/A'),
                'vulns': host.get('vulns', []),
                'data': host.get('data', [])
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def api_info(self):
        """Get API info"""
        try:
            info = self.api.info()
            return {
                'success': True,
                'query_credits': info.get('query_credits', 0),
                'scan_credits': info.get('scan_credits', 0),
                'plan': info.get('plan', 'N/A')
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# --- MAIN GUI APPLICATION ---


# --- NMAP SCANNER ---
class NmapScanner:
    """Nmap port scanner"""
    def __init__(self):
        self.scanner = nmap.PortScanner() if NMAP_AVAILABLE else None
    
    def scan(self, target, ports='1-1000', arguments='-sV'):
        if not NMAP_AVAILABLE:
            return {'success': False, 'error': 'python-nmap not installed. Run: pip install python-nmap'}
        try:
            self.scanner.scan(target, ports, arguments)
            results = {'success': True, 'target': target, 'hosts': {}}
            for host in self.scanner.all_hosts():
                host_info = {
                    'hostname': self.scanner[host].hostname(),
                    'state': self.scanner[host].state(),
                    'protocols': {}
                }
                for proto in self.scanner[host].all_protocols():
                    ports_info = {}
                    for port in self.scanner[host][proto].keys():
                        pd = self.scanner[host][proto][port]
                        ports_info[port] = {
                            'state': pd['state'],
                            'name': pd['name'],
                            'product': pd.get('product', ''),
                            'version': pd.get('version', '')
                        }
                    host_info['protocols'][proto] = ports_info
                results['hosts'][host] = host_info
            return results
        except Exception as e:
            return {'success': False, 'error': str(e)}

# --- WHOIS LOOKUP ---
class WhoisLookup:
    """Whois domain lookup"""
    @staticmethod
    def lookup(domain):
        if not WHOIS_AVAILABLE:
            return {'success': False, 'error': 'python-whois not installed. Run: pip install python-whois'}
        try:
            w = whois_lib.whois(domain)
            return {
                'success': True,
                'domain': domain,
                'registrar': getattr(w, 'registrar', 'N/A'),
                'creation_date': str(getattr(w, 'creation_date', 'N/A')),
                'expiration_date': str(getattr(w, 'expiration_date', 'N/A')),
                'name_servers': getattr(w, 'name_servers', []),
                'status': getattr(w, 'status', 'N/A')
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

# --- DNS ENUMERATOR ---
class DNSEnumerator:
    """DNS enumeration"""
    @staticmethod
    def enumerate(domain, record_types=None):
        if not DNS_AVAILABLE:
            return {'success': False, 'error': 'dnspython not installed. Run: pip install dnspython'}
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        results = {'success': True, 'domain': domain, 'records': {}}
        resolver = dns.resolver.Resolver()
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                if rtype == 'MX':
                    results['records'][rtype] = [f"{r.preference} {r.exchange}" for r in answers]
                else:
                    results['records'][rtype] = [str(r) for r in answers]
            except:
                results['records'][rtype] = []
        return results

# --- SSL ANALYZER ---
class SSLAnalyzer:
    """SSL/TLS certificate analyzer"""
    @staticmethod
    def analyze(hostname, port=443):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        'success': True,
                        'hostname': hostname,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'cipher': cipher,
                        'tls_version': version
                    }
        except Exception as e:
            return {'success': False, 'error': str(e)}

# --- AI ANALYZER ---
class AIAnalyzer:
    """AI-powered security analysis"""
    @staticmethod
    def analyze_with_chatgpt(api_key, scan_results):
        try:
            headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
            prompt = f"""Analyze this security scan result and provide:
1. Summary of findings
2. Identified vulnerabilities
3. Security recommendations
4. Priority actions

Results:
{scan_results}"""
            data = {
                'model': 'gpt-4',
                'messages': [
                    {'role': 'system', 'content': 'You are a cybersecurity expert analyzing scan results.'},
                    {'role': 'user', 'content': prompt}
                ],
                'max_tokens': 2000
            }
            resp = requests.post('https://api.openai.com/v1/chat/completions',
                               headers=headers, json=data, timeout=30)
            if resp.status_code == 200:
                return {'success': True, 'analysis': resp.json()['choices'][0]['message']['content']}
            return {'success': False, 'error': f"API Error: {resp.status_code}"}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def analyze_with_claude(api_key, scan_results):
        try:
            headers = {
                'x-api-key': api_key,
                'Content-Type': 'application/json',
                'anthropic-version': '2023-06-01'
            }
            prompt = f"""Analyze this security scan and provide recommendations:

{scan_results}"""
            data = {
                'model': 'claude-3-5-sonnet-20241022',
                'max_tokens': 2000,
                'messages': [{'role': 'user', 'content': prompt}]
            }
            resp = requests.post('https://api.anthropic.com/v1/messages',
                               headers=headers, json=data, timeout=30)
            if resp.status_code == 200:
                return {'success': True, 'analysis': resp.json()['content'][0]['text']}
            return {'success': False, 'error': f"API Error: {resp.status_code}"}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class CyberSecurityToolkit_GUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Integrated Cybersecurity Toolkit v5.0 - Educational Use Only")
        self.master.geometry("1200x800")
        self.master.resizable(True, True)
        
        # Shodan API instance
        self.shodan_api = None
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_password_cracker_tab()
        self.create_network_tools_tab()
        self.create_shodan_tab()
        
        # Initialize additional tools
        self.nmap_scanner = NmapScanner()
        
        # Create new tabs
        self.create_nmap_tab()
        self.create_whois_tab()
        self.create_dns_tab()
        self.create_ssl_tab()
        self.create_ai_tab()
        self.create_settings_tab()
        
        # Status bar
        self.status_bar = tk.Label(master, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
                
        # Initialize result storage for AI analysis
        self.nmap_last_results = ""
        self.whois_last_results = ""
        self.dns_last_results = ""
        self.ssl_last_results = ""
        
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_password_cracker_tab(self):
        """Create password cracker tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔐 Password Cracker")
        
        # Create sub-notebook for attack types
        attack_notebook = ttk.Notebook(tab)
        attack_notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Offline Attack Tab
        offline_frame = ttk.Frame(attack_notebook)
        attack_notebook.add(offline_frame, text="Offline Attack")
        
        # Hash Input
        hash_frame = ttk.LabelFrame(offline_frame, text="Target Hash", padding=10)
        hash_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(hash_frame, text="Hash String:").grid(row=0, column=0, sticky='w', pady=2)
        self.hash_entry = tk.Entry(hash_frame, width=70)
        self.hash_entry.grid(row=0, column=1, columnspan=2, pady=2, padx=5)
        
        tk.Button(hash_frame, text="Identify Hash", command=self.identify_hash, 
                 bg='#3498db', fg='white', font=('Arial', 9, 'bold')).grid(row=0, column=3, padx=5)
        
        self.hash_type_label = tk.Label(hash_frame, text="Type: Unknown", fg='blue')
        self.hash_type_label.grid(row=1, column=0, columnspan=4, sticky='w', pady=2)
        
        # Attack Configuration
        config_frame = ttk.LabelFrame(offline_frame, text="Attack Configuration", padding=10)
        config_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(config_frame, text="Keywords (CSV):").grid(row=0, column=0, sticky='w')
        self.keywords_entry = tk.Entry(config_frame, width=40)
        self.keywords_entry.grid(row=0, column=1, pady=2, padx=5)
        self.keywords_entry.insert(0, "admin,password,welcome")
        
        tk.Label(config_frame, text="Max Length:").grid(row=0, column=2, sticky='w', padx=(10,0))
        self.max_len_var = tk.IntVar(value=6)
        tk.Spinbox(config_frame, from_=1, to=12, textvariable=self.max_len_var, width=5).grid(row=0, column=3, padx=5)
        
        tk.Label(config_frame, text="Charset:").grid(row=1, column=0, sticky='w')
        self.charset_entry = tk.Entry(config_frame, width=40)
        self.charset_entry.grid(row=1, column=1, pady=2, padx=5)
        self.charset_entry.insert(0, "abcdefghijklmnopqrstuvwxyz0123456789")
        
        tk.Button(config_frame, text="Load Wordlist", command=self.load_external_wordlist,
                 bg='#9b59b6', fg='white').grid(row=1, column=2, columnspan=2, padx=5, sticky='ew')
        
        # Control Buttons
        control_frame = ttk.Frame(offline_frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(control_frame, text="▶️ Start Attack", command=self.start_offline_attack,
                 bg='#27ae60', fg='white', font=('Arial', 11, 'bold'), height=2).pack(side='left', padx=5, fill='x', expand=True)
        
        tk.Button(control_frame, text="⏹️ Stop", command=self.stop_attack,
                 bg='#e74c3c', fg='white', font=('Arial', 11, 'bold'), height=2).pack(side='left', padx=5, fill='x', expand=True)
        
        # Log Output
        log_frame = ttk.LabelFrame(offline_frame, text="Attack Log", padding=5)
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.offline_log = scrolledtext.ScrolledText(log_frame, height=15, bg='black', fg='lime', font=('Courier', 9))
        self.offline_log.pack(fill='both', expand=True)
        
        # Online Attack Tab
        online_frame = ttk.Frame(attack_notebook)
        attack_notebook.add(online_frame, text="Online Attack")
        
        # Target Configuration
        target_frame = ttk.LabelFrame(online_frame, text="Target Configuration", padding=10)
        target_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(target_frame, text="Target:").grid(row=0, column=0, sticky='w')
        self.online_target = tk.Entry(target_frame, width=30)
        self.online_target.grid(row=0, column=1, pady=2, padx=5)
        
        tk.Label(target_frame, text="Port:").grid(row=0, column=2, sticky='w', padx=(10,0))
        self.online_port = tk.Entry(target_frame, width=10)
        self.online_port.grid(row=0, column=3, pady=2, padx=5)
        self.online_port.insert(0, "22")
        
        tk.Label(target_frame, text="Protocol:").grid(row=1, column=0, sticky='w')
        self.online_protocol = ttk.Combobox(target_frame, values=['SSH', 'FTP', 'Telnet'], width=15)
        self.online_protocol.grid(row=1, column=1, pady=2, padx=5)
        self.online_protocol.set('SSH')
        
        # Credentials
        creds_frame = ttk.LabelFrame(online_frame, text="Credentials", padding=10)
        creds_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(creds_frame, text="Usernames (CSV):").grid(row=0, column=0, sticky='w')
        self.online_usernames = tk.Entry(creds_frame, width=60)
        self.online_usernames.grid(row=0, column=1, pady=2, padx=5)
        self.online_usernames.insert(0, "admin,root,user")
        
        tk.Label(creds_frame, text="Passwords (CSV):").grid(row=1, column=0, sticky='w')
        self.online_passwords = tk.Entry(creds_frame, width=60)
        self.online_passwords.grid(row=1, column=1, pady=2, padx=5)
        self.online_passwords.insert(0, "admin,password,123456")
        
        tk.Button(creds_frame, text="Load Password List", command=self.load_password_list,
                 bg='#9b59b6', fg='white').grid(row=1, column=2, padx=5)
        
        # Control Buttons
        online_control_frame = ttk.Frame(online_frame)
        online_control_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(online_control_frame, text="▶️ Start Attack", command=self.start_online_attack,
                 bg='#27ae60', fg='white', font=('Arial', 11, 'bold'), height=2).pack(side='left', padx=5, fill='x', expand=True)
        
        tk.Button(online_control_frame, text="⏹️ Stop", command=self.stop_attack,
                 bg='#e74c3c', fg='white', font=('Arial', 11, 'bold'), height=2).pack(side='left', padx=5, fill='x', expand=True)
        
        # Log Output
        online_log_frame = ttk.LabelFrame(online_frame, text="Attack Log", padding=5)
        online_log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.online_log = scrolledtext.ScrolledText(online_log_frame, height=12, bg='black', fg='yellow', font=('Courier', 9))
        self.online_log.pack(fill='both', expand=True)
    
    def create_network_tools_tab(self):
        """Create network diagnostic tools tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 Network Tools")
        
        # Ping Tool
        ping_frame = ttk.LabelFrame(tab, text="Ping - Network Connectivity Analysis", padding=10)
        ping_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input Frame
        input_frame = ttk.Frame(ping_frame)
        input_frame.pack(fill='x', pady=5)
        
        tk.Label(input_frame, text="Target Host/IP:", font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        self.ping_target = tk.Entry(input_frame, width=40, font=('Arial', 10))
        self.ping_target.pack(side='left', padx=5)
        self.ping_target.insert(0, "8.8.8.8")
        
        tk.Label(input_frame, text="Count:", font=('Arial', 10)).pack(side='left', padx=(20,5))
        self.ping_count = tk.Spinbox(input_frame, from_=1, to=100, width=10)
        self.ping_count.pack(side='left', padx=5)
        self.ping_count.delete(0, tk.END)
        self.ping_count.insert(0, "4")
        
        tk.Label(input_frame, text="Timeout:", font=('Arial', 10)).pack(side='left', padx=(20,5))
        self.ping_timeout = tk.Spinbox(input_frame, from_=1, to=30, width=10)
        self.ping_timeout.pack(side='left', padx=5)
        self.ping_timeout.delete(0, tk.END)
        self.ping_timeout.insert(0, "2")
        
        # Control Buttons
        button_frame = ttk.Frame(ping_frame)
        button_frame.pack(fill='x', pady=10)
        
        tk.Button(button_frame, text="🔍 Start Ping", command=self.start_ping,
                 bg='#3498db', fg='white', font=('Arial', 11, 'bold'), height=2).pack(side='left', padx=5, fill='x', expand=True)
        
        tk.Button(button_frame, text="🔄 Resolve Hostname", command=self.resolve_hostname,
                 bg='#9b59b6', fg='white', font=('Arial', 11, 'bold'), height=2).pack(side='left', padx=5, fill='x', expand=True)
        
        tk.Button(button_frame, text="🗑️ Clear Output", command=self.clear_ping_output,
                 bg='#e67e22', fg='white', font=('Arial', 11, 'bold'), height=2).pack(side='left', padx=5, fill='x', expand=True)
        
        # Results Display
        results_frame = ttk.LabelFrame(ping_frame, text="Ping Results", padding=5)
        results_frame.pack(fill='both', expand=True, pady=5)
        
        self.ping_output = scrolledtext.ScrolledText(results_frame, height=20, bg='#1e1e1e', fg='#00ff00', 
                                                     font=('Courier New', 10), wrap=tk.WORD)
        self.ping_output.pack(fill='both', expand=True)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(ping_frame, text="Quick Statistics", padding=5)
        stats_frame.pack(fill='x', pady=5)
        
        self.ping_stats_label = tk.Label(stats_frame, text="No ping executed yet", 
                                         font=('Arial', 10), fg='blue', justify='left')
        self.ping_stats_label.pack(fill='x', padx=5, pady=5)
    
    def create_shodan_tab(self):
        """Create Shodan reconnaissance tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔎 Shodan Recon")
        
        # API Configuration
        api_frame = ttk.LabelFrame(tab, text="Shodan API Configuration", padding=10)
        api_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(api_frame, text="API Key:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.shodan_api_key = tk.Entry(api_frame, width=50, show='*', font=('Arial', 10))
        self.shodan_api_key.grid(row=0, column=1, padx=5, pady=5)
        self.shodan_api_key.insert(0, "hv44TqZBaVwFPfDMz09m7m2vQKoVADUI")
        
        tk.Button(api_frame, text="🔗 Connect", command=self.connect_shodan,
                 bg='#27ae60', fg='white', font=('Arial', 10, 'bold')).grid(row=0, column=2, padx=5, pady=5)
        
        tk.Button(api_frame, text="ℹ️ API Info", command=self.show_shodan_info,
                 bg='#3498db', fg='white', font=('Arial', 10, 'bold')).grid(row=0, column=3, padx=5, pady=5)
        
        self.shodan_status_label = tk.Label(api_frame, text="Status: Not Connected", fg='red', font=('Arial', 9))
        self.shodan_status_label.grid(row=1, column=0, columnspan=4, sticky='w', padx=5, pady=2)
        
        # Search Tools
        search_notebook = ttk.Notebook(tab)
        search_notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # General Search Tab
        search_frame = ttk.Frame(search_notebook)
        search_notebook.add(search_frame, text="General Search")
        
        search_input_frame = ttk.Frame(search_frame)
        search_input_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(search_input_frame, text="Search Query:", font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        self.shodan_query = tk.Entry(search_input_frame, width=50, font=('Arial', 10))
        self.shodan_query.pack(side='left', padx=5, fill='x', expand=True)
        self.shodan_query.insert(0, "apache")
        
        tk.Label(search_input_frame, text="Limit:", font=('Arial', 10)).pack(side='left', padx=(20,5))
        self.shodan_limit = tk.Spinbox(search_input_frame, from_=1, to=100, width=10)
        self.shodan_limit.pack(side='left', padx=5)
        self.shodan_limit.delete(0, tk.END)
        self.shodan_limit.insert(0, "10")
        
        tk.Button(search_input_frame, text="🔍 Search", command=self.shodan_search,
                 bg='#e74c3c', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=10)
        
        search_results_frame = ttk.LabelFrame(search_frame, text="Search Results", padding=5)
        search_results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.shodan_search_output = scrolledtext.ScrolledText(search_results_frame, height=20, 
                                                             bg='#1e1e1e', fg='#00ffff', 
                                                             font=('Courier New', 9), wrap=tk.WORD)
        self.shodan_search_output.pack(fill='both', expand=True)
        
        # Host Lookup Tab
        host_frame = ttk.Frame(search_notebook)
        search_notebook.add(host_frame, text="Host Lookup")
        
        host_input_frame = ttk.Frame(host_frame)
        host_input_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(host_input_frame, text="Target IP:", font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        self.shodan_host_ip = tk.Entry(host_input_frame, width=30, font=('Arial', 10))
        self.shodan_host_ip.pack(side='left', padx=5)
        self.shodan_host_ip.insert(0, "8.8.8.8")
        
        tk.Button(host_input_frame, text="🎯 Lookup Host", command=self.shodan_host_lookup,
                 bg='#9b59b6', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=10)
        
        tk.Button(host_input_frame, text="🗑️ Clear", command=self.clear_shodan_output,
                 bg='#e67e22', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        
        host_results_frame = ttk.LabelFrame(host_frame, text="Host Information", padding=5)
        host_results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.shodan_host_output = scrolledtext.ScrolledText(host_results_frame, height=20, 
                                                           bg='#1e1e1e', fg='#ffff00', 
                                                           font=('Courier New', 9), wrap=tk.WORD)
        self.shodan_host_output.pack(fill='both', expand=True)
        
        # Common Queries Help
        help_frame = ttk.LabelFrame(tab, text="Common Search Queries", padding=5)
        help_frame.pack(fill='x', padx=10, pady=5)
        
        help_text = (
            "Examples: apache, nginx, port:22, country:US, city:London, "
            "org:\"Google\", product:MySQL, vuln:CVE-2021-44228"
        )
        tk.Label(help_frame, text=help_text, font=('Arial', 9), fg='blue', wraplength=1000, justify='left').pack(padx=5, pady=5)
    
    def create_settings_tab(self):
        """Create settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚙️ Settings")
        
        # Performance Settings
        perf_frame = ttk.LabelFrame(tab, text="Performance Settings", padding=15)
        perf_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(perf_frame, text="CPU Workers:", font=('Arial', 10)).grid(row=0, column=0, sticky='w', pady=5)
        self.cpu_var = tk.IntVar(value=DEFAULT_CPU_THREADS)
        tk.Spinbox(perf_frame, from_=1, to=32, textvariable=self.cpu_var, width=10).grid(row=0, column=1, sticky='w', padx=10)
        
        tk.Label(perf_frame, text="Unlimited Mode:", font=('Arial', 10)).grid(row=1, column=0, sticky='w', pady=5)
        self.unlimited_var = tk.BooleanVar(value=False)
        tk.Checkbutton(perf_frame, variable=self.unlimited_var).grid(row=1, column=1, sticky='w', padx=10)
        
        tk.Label(perf_frame, text="Max Attempts (if limited):", font=('Arial', 10)).grid(row=2, column=0, sticky='w', pady=5)
        self.max_attempts_var = tk.IntVar(value=100000)
        tk.Entry(perf_frame, textvariable=self.max_attempts_var, width=15).grid(row=2, column=1, sticky='w', padx=10)
        
        # Online Attack Settings
        online_frame = ttk.LabelFrame(tab, text="Online Attack Settings", padding=15)
        online_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(online_frame, text="Connection Timeout (s):", font=('Arial', 10)).grid(row=0, column=0, sticky='w', pady=5)
        self.timeout_var = tk.IntVar(value=5)
        tk.Spinbox(online_frame, from_=1, to=30, textvariable=self.timeout_var, width=10).grid(row=0, column=1, sticky='w', padx=10)
        
        tk.Label(online_frame, text="Delay Between Attempts (s):", font=('Arial', 10)).grid(row=1, column=0, sticky='w', pady=5)
        self.delay_var = tk.DoubleVar(value=0.1)
        tk.Spinbox(online_frame, from_=0.0, to=5.0, increment=0.1, textvariable=self.delay_var, width=10).grid(row=1, column=1, sticky='w', padx=10)
        
        tk.Label(online_frame, text="Parallel Threads:", font=('Arial', 10)).grid(row=2, column=0, sticky='w', pady=5)
        self.online_threads_var = tk.IntVar(value=4)
        tk.Spinbox(online_frame, from_=1, to=16, textvariable=self.online_threads_var, width=10).grid(row=2, column=1, sticky='w', padx=10)
        
        # Save Button
        tk.Button(tab, text="💾 Save Settings", command=self.save_settings,
                 bg='#27ae60', fg='white', font=('Arial', 12, 'bold'), height=2).pack(pady=20, padx=10, fill='x')
        
        # About Section
        about_frame = ttk.LabelFrame(tab, text="About", padding=15)
        about_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        about_text = """
        Integrated Cybersecurity Toolkit v5.0
        
        This toolkit combines essential security testing tools:
        
        • Password Cracker: Advanced hash cracking with GPU/CPU support
        • Network Tools: Ping and connectivity diagnostics
        • Shodan Integration: Reconnaissance and OSINT capabilities
        
        Features:
        - Dictionary and brute-force attacks
        - Multiple hash algorithm support
        - Network diagnostic utilities
        - Internet-wide device reconnaissance
        - Modular architecture for expansion
        
        Author: Dr. Mohammed Tawfik
        Email: kmkhol01@gmail.com
        
        ⚠️  WARNING: EDUCATIONAL USE ONLY
        Unauthorized use is illegal and unethical.
        """
        
        tk.Label(about_frame, text=about_text, font=('Arial', 9), justify='left').pack(padx=10, pady=10)
    
    # Password Cracker Methods
    def log(self, message, target='offline'):
        """Log message to appropriate console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        if target == 'offline':
            self.offline_log.insert(tk.END, log_message)
            self.offline_log.see(tk.END)
        elif target == 'online':
            self.online_log.insert(tk.END, log_message)
            self.online_log.see(tk.END)
        
        self.master.update_idletasks()
    
    def identify_hash(self):
        """Identify hash type"""
        hash_string = self.hash_entry.get().strip()
        if not hash_string:
            messagebox.showwarning("Warning", "Enter a hash string")
            return
        
        hash_type, recommendation = identify_hash(hash_string)
        self.hash_type_label.config(text=f"Type: {hash_type} | {recommendation}")
        self.log(f"[HASH] Identified as: {hash_type}", 'offline')
        self.log(f"[RECOMMEND] {recommendation}", 'offline')
    
    def load_external_wordlist(self):
        """Load external wordlist"""
        filepath = filedialog.askopenfilename(title="Select Wordlist", 
                                              filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            passwords = load_wordlist_from_file(filepath)
            if passwords:
                SETTINGS.loaded_wordlist = passwords
                self.log(f"[WORDLIST] Loaded {len(passwords):,} passwords from file", 'offline')
                messagebox.showinfo("Success", f"Loaded {len(passwords):,} passwords")
    
    def start_offline_attack(self):
        """Start offline attack"""
        hash_string = self.hash_entry.get().strip()
        keywords = self.keywords_entry.get().strip()
        max_len = self.max_len_var.get()
        charset_mask = self.charset_entry.get().strip()
        
        if not hash_string:
            messagebox.showerror("Error", "Enter a hash string")
            return
        
        SETTINGS.attack_stopped = False
        
        thread = threading.Thread(
            target=self._offline_attack_process,
            args=(hash_string, keywords, max_len, charset_mask)
        )
        thread.daemon = True
        thread.start()
        
        self.log("\n=== OFFLINE ATTACK STARTED ===", 'offline')
    
    def _offline_attack_process(self, hash_string, keywords, max_len, charset_mask):
        """Offline attack process"""
        try:
            hash_type, recommendation = identify_hash(hash_string)
            self.log(f"[HASH] Type: {hash_type}", 'offline')
            self.log(f"[RECOMMEND] {recommendation}", 'offline')
            
            if hash_type in ['NetNTLMv2', 'NetNTLMv1', 'UNIX_BCRYPT', 'UNIX_ARGON2']:
                self.log("[STRATEGY] Complex hash - Dictionary only", 'offline')
                
                if SETTINGS.loaded_wordlist:
                    wordlist = SETTINGS.loaded_wordlist
                    self.log(f"[WORDLIST] Using loaded ({len(wordlist):,} words)", 'offline')
                else:
                    wordlist = generate_targeted_wordlist(keywords, 
                                                         (SETTINGS.year_range_start, SETTINGS.year_range_end),
                                                         SETTINGS.use_common_combinations)
                    self.log(f"[WORDLIST] Generated {len(wordlist):,} candidates", 'offline')
                
                password, duration = perform_dictionary_attack(hash_string, hash_type, 
                                                              wordlist, lambda msg: self.log(msg, 'offline'), SETTINGS)
                
                if password:
                    self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {p}\nTime: {d:.2f}s"))
                else:
                    self.master.after(0, lambda d=duration: messagebox.showwarning("❌ Failed", 
                                      f"Failed in {d:.2f}s"))
            
            elif hash_type in ['MD5', 'SHA1', 'SHA256', 'SHA512', 'NTLM', 'MySQL_OLD']:
                self.log("[STRATEGY] Fast hash - Dictionary → Brute Force", 'offline')
                
                # Dictionary
                self.log("[PHASE 1/2] Dictionary Attack", 'offline')
                
                if SETTINGS.loaded_wordlist:
                    wordlist = SETTINGS.loaded_wordlist
                    self.log(f"[WORDLIST] Using loaded ({len(wordlist):,} words)", 'offline')
                else:
                    wordlist = generate_targeted_wordlist(keywords, 
                                                         (SETTINGS.year_range_start, SETTINGS.year_range_end),
                                                         SETTINGS.use_common_combinations)
                    
                    if not keywords.strip():
                        self.log("[INFO] Keywords empty - using common combinations", 'offline')
                    
                    self.log(f"[WORDLIST] Generated {len(wordlist):,} candidates", 'offline')
                
                password, duration = perform_dictionary_attack(hash_string, hash_type, 
                                                              wordlist, lambda msg: self.log(msg, 'offline'), SETTINGS)
                
                if password:
                    self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {p}\nTime: {d:.2f}s"))
                    return
                
                if SETTINGS.attack_stopped:
                    return
                
                # Brute Force
                self.log("[PHASE 2/2] Brute Force Attack", 'offline')
                
                # Parse charset
                if not charset_mask or charset_mask == "?a":
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                elif charset_mask == "?l":
                    charset = "abcdefghijklmnopqrstuvwxyz"
                elif charset_mask == "?u":
                    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                elif charset_mask == "?d":
                    charset = "0123456789"
                elif charset_mask == "?s":
                    charset = "!@#$%^&*()_+-="
                elif charset_mask == "?lu":
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                elif charset_mask == "?lud":
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                else:
                    charset = charset_mask
                
                password, duration = perform_brute_force_unlimited(hash_string, hash_type, max_len, 
                                                                  charset, lambda msg: self.log(msg, 'offline'), SETTINGS)
                if password:
                    self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {p}\nTime: {d:.2f}s"))
                else:
                    self.master.after(0, lambda d=duration: messagebox.showwarning("❌ Failed", 
                                      f"Failed in {d:.2f}s"))
            
            else:
                self.log("[STRATEGY] Unknown - Dictionary fallback", 'offline')
                
                if SETTINGS.loaded_wordlist:
                    wordlist = SETTINGS.loaded_wordlist
                    self.log(f"[WORDLIST] Using loaded ({len(wordlist):,} words)", 'offline')
                else:
                    wordlist = generate_targeted_wordlist(keywords, 
                                                         (SETTINGS.year_range_start, SETTINGS.year_range_end),
                                                         SETTINGS.use_common_combinations)
                
                password, duration = perform_dictionary_attack(hash_string, hash_type, 
                                                              wordlist, lambda msg: self.log(msg, 'offline'), SETTINGS)
                if password:
                    self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {p}\nTime: {d:.2f}s"))
                else:
                    self.master.after(0, lambda d=duration: messagebox.showwarning("❌ Failed", 
                                      f"Failed in {d:.2f}s"))
        
        except Exception as e:
            self.log(f"[ERROR] {str(e)}", 'offline')
            error_msg = str(e)
            self.master.after(0, lambda: messagebox.showerror("Error", error_msg))
    
    def start_online_attack(self):
        """Online attack"""
        target = self.online_target.get().strip()
        port = int(self.online_port.get())
        protocol = self.online_protocol.get()
        usernames = [u.strip() for u in self.online_usernames.get().split(',') if u.strip()]
        passwords = [p.strip() for p in self.online_passwords.get().split(',') if p.strip()]
        
        if not target or not usernames or not passwords:
            messagebox.showerror("Error", "Fill all fields")
            return
        
        SETTINGS.attack_stopped = False
        SETTINGS.online_timeout = self.timeout_var.get()
        SETTINGS.online_delay = self.delay_var.get()
        SETTINGS.online_threads = self.online_threads_var.get()
        
        thread = threading.Thread(
            target=self._online_attack_process,
            args=(target, port, protocol, usernames, passwords)
        )
        thread.daemon = True
        thread.start()
        
        self.log("\n=== ONLINE ATTACK STARTED ===", 'online')
        self.log(f"[TARGET] {protocol}://{target}:{port}", 'online')
    
    def _online_attack_process(self, target, port, protocol, usernames, passwords):
        try:
            attacker = OnlineAttacker(target, port, protocol, lambda msg: self.log(msg, 'online'), SETTINGS)
            result, duration = attacker.attack(usernames, passwords)
            
            if result:
                username, password = result
                self.master.after(0, lambda: messagebox.showinfo("✅ SUCCESS", 
                                  f"Credentials: {username}:{password}\nTime: {duration:.2f}s"))
            else:
                self.master.after(0, lambda: messagebox.showwarning("❌ Failed", 
                                  f"Failed in {duration:.2f}s"))
        except Exception as e:
            error_msg = str(e)
            self.log(f"[ERROR] {error_msg}", 'online')
            self.master.after(0, lambda: messagebox.showerror("Error", error_msg))
    
    def stop_attack(self):
        SETTINGS.attack_stopped = True
        self.log("[CONTROL] ⏹️ Stop signal sent", 'offline')
        self.log("[CONTROL] ⏹️ Stop signal sent", 'online')
    
    def load_password_list(self):
        filepath = filedialog.askopenfilename(title="Select Password List", 
                                              filetypes=[("Text files", "*.txt")])
        if filepath:
            passwords = load_wordlist_from_file(filepath)
            if passwords:
                preview = ', '.join(passwords[:3])
                self.online_passwords.delete(0, tk.END)
                self.online_passwords.insert(0, preview + f"... ({len(passwords)} loaded)")
                self.log(f"[PASSWORDS] Loaded {len(passwords):,} passwords", 'online')
    
    # Network Tools Methods
    def start_ping(self):
        """Start ping operation"""
        target = self.ping_target.get().strip()
        count = int(self.ping_count.get())
        timeout = int(self.ping_timeout.get())
        
        if not target:
            messagebox.showerror("Error", "Enter a target host or IP")
            return
        
        self.ping_output.insert(tk.END, f"\n{'='*80}\n")
        self.ping_output.insert(tk.END, f"Starting ping to {target} with {count} packets...\n")
        self.ping_output.insert(tk.END, f"{'='*80}\n\n")
        self.ping_output.see(tk.END)
        
        thread = threading.Thread(target=self._ping_process, args=(target, count, timeout))
        thread.daemon = True
        thread.start()
    
    def _ping_process(self, target, count, timeout):
        """Ping process"""
        try:
            results = NetworkTools.ping(target, count, timeout)
            
            self.master.after(0, lambda: self.ping_output.insert(tk.END, results['output']))
            self.master.after(0, lambda: self.ping_output.insert(tk.END, "\n"))
            
            if results['success']:
                stats_text = (
                    f"✅ Packets: Sent={results['sent']}, Received={results['received']}, "
                    f"Lost={results['lost']} ({results['loss_percent']:.1f}% loss) | "
                    f"RTT: Min={results['min_time']}ms, Avg={results['avg_time']:.1f}ms, "
                    f"Max={results['max_time']}ms"
                )
                self.master.after(0, lambda: self.ping_output.insert(tk.END, f"\n{stats_text}\n"))
                self.master.after(0, lambda: self.ping_stats_label.config(text=stats_text, fg='green'))
            else:
                error_text = f"❌ Ping failed: {results['error']}"
                self.master.after(0, lambda: self.ping_output.insert(tk.END, f"\n{error_text}\n"))
                self.master.after(0, lambda: self.ping_stats_label.config(text=error_text, fg='red'))
            
            self.master.after(0, lambda: self.ping_output.see(tk.END))
            
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.master.after(0, lambda: self.ping_output.insert(tk.END, f"\n{error_msg}\n"))
            self.master.after(0, lambda: self.ping_stats_label.config(text=error_msg, fg='red'))
    
    def resolve_hostname(self):
        """Resolve hostname to IP"""
        target = self.ping_target.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Enter a hostname")
            return
        
        self.ping_output.insert(tk.END, f"\n{'='*80}\n")
        self.ping_output.insert(tk.END, f"Resolving hostname: {target}\n")
        self.ping_output.insert(tk.END, f"{'='*80}\n\n")
        
        result = NetworkTools.resolve_hostname(target)
        
        if result['success']:
            output = f"✅ Hostname: {result['hostname']}\n   IP Address: {result['ip']}\n"
            self.ping_output.insert(tk.END, output)
            self.ping_stats_label.config(text=f"Resolved: {result['hostname']} → {result['ip']}", fg='green')
        else:
            output = f"❌ Resolution failed: {result['error']}\n"
            self.ping_output.insert(tk.END, output)
            self.ping_stats_label.config(text=f"Failed to resolve {target}", fg='red')
        
        self.ping_output.see(tk.END)
    
    def clear_ping_output(self):
        """Clear ping output"""
        self.ping_output.delete(1.0, tk.END)
        self.ping_stats_label.config(text="Output cleared", fg='blue')
    
    # Shodan Methods
    def connect_shodan(self):
        """Connect to Shodan API"""
        api_key = self.shodan_api_key.get().strip()
        
        if not api_key:
            messagebox.showerror("Error", "Enter Shodan API key")
            return
        
        try:
            self.shodan_api = ShodanScanner(api_key)
            self.shodan_status_label.config(text="Status: ✅ Connected", fg='green')
            messagebox.showinfo("Success", "Connected to Shodan API")
            
            # Get API info
            info = self.shodan_api.api_info()
            if info['success']:
                info_text = f"Plan: {info['plan']} | Query Credits: {info['query_credits']}"
                self.shodan_status_label.config(text=f"Status: ✅ Connected | {info_text}", fg='green')
        
        except Exception as e:
            self.shodan_status_label.config(text="Status: ❌ Connection Failed", fg='red')
            messagebox.showerror("Error", str(e))
    
    def show_shodan_info(self):
        """Show Shodan API info"""
        if not self.shodan_api:
            messagebox.showwarning("Warning", "Connect to Shodan first")
            return
        
        info = self.shodan_api.api_info()
        
        if info['success']:
            messagebox.showinfo("Shodan API Info", 
                              f"Plan: {info['plan']}\n"
                              f"Query Credits: {info['query_credits']}\n"
                              f"Scan Credits: {info['scan_credits']}")
        else:
            messagebox.showerror("Error", info['error'])
    
    def shodan_search(self):
        """Perform Shodan search"""
        if not self.shodan_api:
            messagebox.showwarning("Warning", "Connect to Shodan first")
            return
        
        query = self.shodan_query.get().strip()
        limit = int(self.shodan_limit.get())
        
        if not query:
            messagebox.showerror("Error", "Enter a search query")
            return
        
        self.shodan_search_output.delete(1.0, tk.END)
        self.shodan_search_output.insert(tk.END, f"Searching Shodan for: {query}\n")
        self.shodan_search_output.insert(tk.END, f"{'='*80}\n\n")
        
        thread = threading.Thread(target=self._shodan_search_process, args=(query, limit))
        thread.daemon = True
        thread.start()
    
    def _shodan_search_process(self, query, limit):
        """Shodan search process"""
        try:
            results = self.shodan_api.search(query, limit)
            
            if results['success']:
                output = f"Total results found: {results['total']:,}\n"
                output += f"Showing top {len(results['matches'])} results:\n\n"
                
                for i, match in enumerate(results['matches'], 1):
                    output += f"{'─'*80}\n"
                    output += f"Result #{i}\n"
                    output += f"{'─'*80}\n"
                    output += f"IP: {match.get('ip_str', 'N/A')}\n"
                    output += f"Port: {match.get('port', 'N/A')}\n"
                    output += f"Organization: {match.get('org', 'N/A')}\n"
                    output += f"Hostnames: {', '.join(match.get('hostnames', [])) or 'N/A'}\n"
                    output += f"Country: {match.get('location', {}).get('country_name', 'N/A')}\n"
                    output += f"City: {match.get('location', {}).get('city', 'N/A')}\n"
                    output += f"Product: {match.get('product', 'N/A')}\n"
                    output += f"Version: {match.get('version', 'N/A')}\n"
                    
                    if match.get('data'):
                        output += f"\nBanner:\n{match['data'][:200]}...\n"
                    
                    output += "\n"
                
                self.master.after(0, lambda: self.shodan_search_output.insert(tk.END, output))
            else:
                error_output = f"❌ Search failed: {results['error']}\n"
                self.master.after(0, lambda: self.shodan_search_output.insert(tk.END, error_output))
            
            self.master.after(0, lambda: self.shodan_search_output.see(tk.END))
        
        except Exception as e:
            error_msg = f"Error: {str(e)}\n"
            self.master.after(0, lambda: self.shodan_search_output.insert(tk.END, error_msg))
    
    def shodan_host_lookup(self):
        """Perform Shodan host lookup"""
        if not self.shodan_api:
            messagebox.showwarning("Warning", "Connect to Shodan first")
            return
        
        ip = self.shodan_host_ip.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Enter an IP address")
            return
        
        self.shodan_host_output.delete(1.0, tk.END)
        self.shodan_host_output.insert(tk.END, f"Looking up host: {ip}\n")
        self.shodan_host_output.insert(tk.END, f"{'='*80}\n\n")
        
        thread = threading.Thread(target=self._shodan_host_process, args=(ip,))
        thread.daemon = True
        thread.start()
    
    def _shodan_host_process(self, ip):
        """Shodan host lookup process"""
        try:
            results = self.shodan_api.host_info(ip)
            
            if results['success']:
                output = f"🎯 Host Information for {results['ip']}\n\n"
                output += f"Organization: {results['organization']}\n"
                output += f"Operating System: {results['operating_system']}\n"
                output += f"Country: {results['country']}\n"
                output += f"City: {results['city']}\n"
                output += f"ISP: {results['isp']}\n"
                output += f"Hostnames: {', '.join(results['hostnames']) or 'N/A'}\n"
                output += f"\nOpen Ports: {', '.join(map(str, results['ports'])) or 'None detected'}\n"
                
                if results['vulns']:
                    output += f"\n⚠️ Vulnerabilities Found: {', '.join(results['vulns'])}\n"
                
                output += f"\n{'─'*80}\n"
                output += "Service Details:\n"
                output += f"{'─'*80}\n\n"
                
                for service in results['data'][:5]:
                    output += f"Port: {service.get('port', 'N/A')}\n"
                    output += f"Transport: {service.get('transport', 'N/A')}\n"
                    output += f"Product: {service.get('product', 'N/A')}\n"
                    
                    if service.get('data'):
                        output += f"Banner:\n{service['data'][:200]}...\n"
                    
                    output += "\n"
                
                self.master.after(0, lambda: self.shodan_host_output.insert(tk.END, output))
            else:
                error_output = f"❌ Lookup failed: {results['error']}\n"
                self.master.after(0, lambda: self.shodan_host_output.insert(tk.END, error_output))
            
            self.master.after(0, lambda: self.shodan_host_output.see(tk.END))
        
        except Exception as e:
            error_msg = f"Error: {str(e)}\n"
            self.master.after(0, lambda: self.shodan_host_output.insert(tk.END, error_msg))
    
    def clear_shodan_output(self):
        """Clear Shodan output"""
        self.shodan_host_output.delete(1.0, tk.END)
    
    # Settings Methods
    def save_settings(self):
        try:
            SETTINGS.cpu_workers = self.cpu_var.get()
            SETTINGS.online_timeout = self.timeout_var.get()
            SETTINGS.online_delay = self.delay_var.get()
            SETTINGS.online_threads = self.online_threads_var.get()
            SETTINGS.unlimited_mode = self.unlimited_var.get()
            SETTINGS.max_attempts = self.max_attempts_var.get()
            
            self.log("[CONFIG] Settings saved", 'offline')
            messagebox.showinfo("Success", "Configuration saved successfully")
        except Exception as e:
            messagebox.showerror("Error", str(e))


    def create_nmap_tab(self):
        """Nmap scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 Nmap Scanner")
        
        input_frame = ttk.LabelFrame(tab, text="Scan Configuration", padding=10)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(input_frame, text="Target:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=5)
        self.nmap_target = tk.Entry(input_frame, width=35, font=('Arial', 10))
        self.nmap_target.grid(row=0, column=1, padx=5)
        self.nmap_target.insert(0, "scanme.nmap.org")
        
        tk.Label(input_frame, text="Ports:", font=('Arial', 10)).grid(row=0, column=2, sticky='w', padx=5)
        self.nmap_ports = tk.Entry(input_frame, width=15)
        self.nmap_ports.grid(row=0, column=3, padx=5)
        self.nmap_ports.insert(0, "1-1000")
        
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill='x', padx=10, pady=10)
        tk.Button(btn_frame, text="🚀 Start Scan", command=self.start_nmap,
                 bg='#27ae60', fg='white', font=('Arial', 11, 'bold')).pack(side='left', padx=5, fill='x', expand=True)
        tk.Button(btn_frame, text="🤖 Analyze with AI", command=lambda: self.ai_analyze_results('nmap'),
                 bg='#9b59b6', fg='white', font=('Arial', 11, 'bold')).pack(side='left', padx=5, fill='x', expand=True)
        
        results_frame = ttk.LabelFrame(tab, text="Scan Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        self.nmap_output = scrolledtext.ScrolledText(results_frame, height=20, bg='#1e1e1e', fg='#00ff00', font=('Courier', 9))
        self.nmap_output.pack(fill='both', expand=True)
    
    def start_nmap(self):
        target = self.nmap_target.get().strip()
        ports = self.nmap_ports.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter target")
            return
        self.nmap_output.insert(tk.END, f"\nScanning {target}...\n")
        threading.Thread(target=self._nmap_scan, args=(target, ports), daemon=True).start()
    
    def _nmap_scan(self, target, ports):
        results = self.nmap_scanner.scan(target, ports, '-sV')
        if results['success']:
            out = f"\n{'='*70}\nScan Results for {target}\n{'='*70}\n"
            for host, data in results['hosts'].items():
                out += f"\nHost: {host} ({data['hostname']}) - State: {data['state']}\n"
                for proto, pdata in data['protocols'].items():
                    out += f"\n{proto.upper()} Ports:\n"
                    for port, info in pdata.items():
                        out += f"  {port}: {info['state']} - {info['name']} {info['product']} {info['version']}\n"
            self.master.after(0, lambda: self.nmap_output.insert(tk.END, out))
            self.nmap_last_results = out
        else:
            self.master.after(0, lambda: self.nmap_output.insert(tk.END, f"Error: {results['error']}\n"))
    
    def create_whois_tab(self):
        """Whois lookup tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔎 Whois Lookup")
        
        input_frame = ttk.LabelFrame(tab, text="Domain Lookup", padding=10)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(input_frame, text="Domain:", font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        self.whois_domain = tk.Entry(input_frame, width=40, font=('Arial', 10))
        self.whois_domain.pack(side='left', padx=5, fill='x', expand=True)
        self.whois_domain.insert(0, "example.com")
        
        tk.Button(input_frame, text="🔍 Lookup", command=self.start_whois,
                 bg='#3498db', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        tk.Button(input_frame, text="🤖 AI Analyze", command=lambda: self.ai_analyze_results('whois'),
                 bg='#9b59b6', fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        
        results_frame = ttk.LabelFrame(tab, text="Whois Information", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        self.whois_output = scrolledtext.ScrolledText(results_frame, height=25, bg='#1e1e1e', fg='#00ffff', font=('Courier', 9))
        self.whois_output.pack(fill='both', expand=True)
    
    def start_whois(self):
        domain = self.whois_domain.get().strip()
        if not domain:
            messagebox.showerror("Error", "Enter domain")
            return
        self.whois_output.insert(tk.END, f"\nLooking up {domain}...\n")
        threading.Thread(target=self._whois_lookup, args=(domain,), daemon=True).start()
    
    def _whois_lookup(self, domain):
        results = WhoisLookup.lookup(domain)
        if results['success']:
            out = f"\n{'='*70}\nWhois Information for {domain}\n{'='*70}\n"
            out += f"Registrar: {results['registrar']}\n"
            out += f"Creation Date: {results['creation_date']}\n"
            out += f"Expiration Date: {results['expiration_date']}\n"
            out += f"Status: {results['status']}\n"
            out += f"Name Servers: {', '.join(results['name_servers']) if results['name_servers'] else 'N/A'}\n"
            self.master.after(0, lambda: self.whois_output.insert(tk.END, out))
            self.whois_last_results = out
        else:
            self.master.after(0, lambda: self.whois_output.insert(tk.END, f"Error: {results['error']}\n"))
    
    def create_dns_tab(self):
        """DNS enumeration tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌍 DNS Enumeration")
        
        input_frame = ttk.LabelFrame(tab, text="DNS Configuration", padding=10)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(input_frame, text="Domain:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=5)
        self.dns_domain = tk.Entry(input_frame, width=35, font=('Arial', 10))
        self.dns_domain.grid(row=0, column=1, padx=5)
        self.dns_domain.insert(0, "google.com")
        
        tk.Label(input_frame, text="Records:", font=('Arial', 10)).grid(row=0, column=2, sticky='w', padx=5)
        self.dns_records = tk.Entry(input_frame, width=25)
        self.dns_records.grid(row=0, column=3, padx=5)
        self.dns_records.insert(0, "A,AAAA,MX,NS,TXT")
        
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill='x', padx=10, pady=10)
        tk.Button(btn_frame, text="🔍 Enumerate", command=self.start_dns,
                 bg='#27ae60', fg='white', font=('Arial', 11, 'bold')).pack(side='left', padx=5, fill='x', expand=True)
        tk.Button(btn_frame, text="🤖 AI Analyze", command=lambda: self.ai_analyze_results('dns'),
                 bg='#9b59b6', fg='white', font=('Arial', 11, 'bold')).pack(side='left', padx=5, fill='x', expand=True)
        
        results_frame = ttk.LabelFrame(tab, text="DNS Records", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        self.dns_output = scrolledtext.ScrolledText(results_frame, height=25, bg='#1e1e1e', fg='#ffff00', font=('Courier', 9))
        self.dns_output.pack(fill='both', expand=True)
    
    def start_dns(self):
        domain = self.dns_domain.get().strip()
        records = [r.strip() for r in self.dns_records.get().split(',')]
        if not domain:
            messagebox.showerror("Error", "Enter domain")
            return
        self.dns_output.insert(tk.END, f"\nEnumerating {domain}...\n")
        threading.Thread(target=self._dns_enum, args=(domain, records), daemon=True).start()
    
    def _dns_enum(self, domain, records):
        results = DNSEnumerator.enumerate(domain, records)
        if results['success']:
            out = f"\n{'='*70}\nDNS Records for {domain}\n{'='*70}\n"
            for rtype, data in results['records'].items():
                out += f"\n{rtype} Records:\n"
                if data:
                    for record in data:
                        out += f"  {record}\n"
                else:
                    out += "  (none found)\n"
            self.master.after(0, lambda: self.dns_output.insert(tk.END, out))
            self.dns_last_results = out
        else:
            self.master.after(0, lambda: self.dns_output.insert(tk.END, f"Error: {results['error']}\n"))
    
    def create_ssl_tab(self):
        """SSL/TLS analyzer tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔒 SSL/TLS Analyzer")
        
        input_frame = ttk.LabelFrame(tab, text="SSL Configuration", padding=10)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(input_frame, text="Hostname:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=5)
        self.ssl_hostname = tk.Entry(input_frame, width=35, font=('Arial', 10))
        self.ssl_hostname.grid(row=0, column=1, padx=5)
        self.ssl_hostname.insert(0, "www.google.com")
        
        tk.Label(input_frame, text="Port:", font=('Arial', 10)).grid(row=0, column=2, sticky='w', padx=5)
        self.ssl_port = tk.Entry(input_frame, width=10)
        self.ssl_port.grid(row=0, column=3, padx=5)
        self.ssl_port.insert(0, "443")
        
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill='x', padx=10, pady=10)
        tk.Button(btn_frame, text="🔍 Analyze", command=self.start_ssl,
                 bg='#27ae60', fg='white', font=('Arial', 11, 'bold')).pack(side='left', padx=5, fill='x', expand=True)
        tk.Button(btn_frame, text="🤖 AI Analyze", command=lambda: self.ai_analyze_results('ssl'),
                 bg='#9b59b6', fg='white', font=('Arial', 11, 'bold')).pack(side='left', padx=5, fill='x', expand=True)
        
        results_frame = ttk.LabelFrame(tab, text="Certificate Information", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        self.ssl_output = scrolledtext.ScrolledText(results_frame, height=25, bg='#1e1e1e', fg='#ff00ff', font=('Courier', 9))
        self.ssl_output.pack(fill='both', expand=True)
    
    def start_ssl(self):
        hostname = self.ssl_hostname.get().strip()
        port = int(self.ssl_port.get())
        if not hostname:
            messagebox.showerror("Error", "Enter hostname")
            return
        self.ssl_output.insert(tk.END, f"\nAnalyzing {hostname}:{port}...\n")
        threading.Thread(target=self._ssl_analyze, args=(hostname, port), daemon=True).start()
    
    def _ssl_analyze(self, hostname, port):
        results = SSLAnalyzer.analyze(hostname, port)
        if results['success']:
            out = f"\n{'='*70}\nSSL/TLS Certificate for {hostname}\n{'='*70}\n"
            out += f"Subject: {results['subject']}\n"
            out += f"Issuer: {results['issuer']}\n"
            out += f"Valid From: {results['not_before']}\n"
            out += f"Valid Until: {results['not_after']}\n"
            out += f"Version: {results['version']}\n"
            out += f"Serial: {results['serial']}\n"
            out += f"Cipher: {results['cipher']}\n"
            out += f"TLS Version: {results['tls_version']}\n"
            self.master.after(0, lambda: self.ssl_output.insert(tk.END, out))
            self.ssl_last_results = out
        else:
            self.master.after(0, lambda: self.ssl_output.insert(tk.END, f"Error: {results['error']}\n"))
    
    def create_ai_tab(self):
        """AI analysis tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🤖 AI Analysis")
        
        api_frame = ttk.LabelFrame(tab, text="API Configuration", padding=15)
        api_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(api_frame, text="Provider:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=5)
        self.ai_provider = tk.StringVar(value="chatgpt")
        ttk.Radiobutton(api_frame, text="ChatGPT", variable=self.ai_provider, value="chatgpt").grid(row=0, column=1, padx=5)
        ttk.Radiobutton(api_frame, text="Claude", variable=self.ai_provider, value="claude").grid(row=0, column=2, padx=5)
        
        tk.Label(api_frame, text="ChatGPT Key:", font=('Arial', 10)).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.chatgpt_key = tk.Entry(api_frame, width=50, show='*', font=('Arial', 9))
        self.chatgpt_key.grid(row=1, column=1, columnspan=2, sticky='ew', padx=5)
        
        tk.Label(api_frame, text="Claude Key:", font=('Arial', 10)).grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.claude_key = tk.Entry(api_frame, width=50, show='*', font=('Arial', 9))
        self.claude_key.grid(row=2, column=1, columnspan=2, sticky='ew', padx=5)
        
        input_frame = ttk.LabelFrame(tab, text="Paste Scan Results", padding=10)
        input_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.ai_input = scrolledtext.ScrolledText(input_frame, height=10, font=('Courier', 9))
        self.ai_input.pack(fill='both', expand=True, padx=5, pady=5)
        
        tk.Button(input_frame, text="🤖 Analyze with AI", command=self.manual_ai_analyze,
                 bg='#9b59b6', fg='white', font=('Arial', 11, 'bold'), height=2).pack(pady=5, fill='x')
        
        results_frame = ttk.LabelFrame(tab, text="AI Analysis Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.ai_output = scrolledtext.ScrolledText(results_frame, height=15, bg='#1e1e1e', fg='#00ff00', font=('Courier', 9))
        self.ai_output.pack(fill='both', expand=True)
    
    def ai_analyze_results(self, source):
        """Analyze results from different tabs"""
        scan_data = ""
        if source == 'nmap' and hasattr(self, 'nmap_last_results'):
            scan_data = self.nmap_last_results
        elif source == 'whois' and hasattr(self, 'whois_last_results'):
            scan_data = self.whois_last_results
        elif source == 'dns' and hasattr(self, 'dns_last_results'):
            scan_data = self.dns_last_results
        elif source == 'ssl' and hasattr(self, 'ssl_last_results'):
            scan_data = self.ssl_last_results
        
        if not scan_data:
            messagebox.showwarning("No Data", f"No {source} results to analyze. Run a scan first.")
            return
        
        self.ai_input.delete(1.0, tk.END)
        self.ai_input.insert(tk.END, scan_data)
        self.notebook.select(self.notebook.tabs()[-1])  # Switch to AI tab
        self.manual_ai_analyze()
    
    def manual_ai_analyze(self):
        """Manual AI analysis"""
        scan_results = self.ai_input.get(1.0, tk.END).strip()
        if not scan_results:
            messagebox.showerror("Error", "Enter scan results")
            return
        
        provider = self.ai_provider.get()
        if provider == "chatgpt":
            api_key = self.chatgpt_key.get().strip()
            if not api_key:
                messagebox.showerror("Error", "Enter ChatGPT API key")
                return
            self.ai_output.insert(tk.END, "\nAnalyzing with ChatGPT...\n")
            threading.Thread(target=self._ai_analyze_chatgpt, args=(api_key, scan_results), daemon=True).start()
        else:
            api_key = self.claude_key.get().strip()
            if not api_key:
                messagebox.showerror("Error", "Enter Claude API key")
                return
            self.ai_output.insert(tk.END, "\nAnalyzing with Claude...\n")
            threading.Thread(target=self._ai_analyze_claude, args=(api_key, scan_results), daemon=True).start()
    
    def _ai_analyze_chatgpt(self, api_key, results):
        result = AIAnalyzer.analyze_with_chatgpt(api_key, results)
        if result['success']:
            self.master.after(0, lambda: self.ai_output.insert(tk.END, f"\n{'='*70}\n{result['analysis']}\n"))
        else:
            self.master.after(0, lambda: self.ai_output.insert(tk.END, f"\nError: {result['error']}\n"))
    
    def _ai_analyze_claude(self, api_key, results):
        result = AIAnalyzer.analyze_with_claude(api_key, results)
        if result['success']:
            self.master.after(0, lambda: self.ai_output.insert(tk.END, f"\n{'='*70}\n{result['analysis']}\n"))
        else:
            self.master.after(0, lambda: self.ai_output.insert(tk.END, f"\nError: {result['error']}\n"))


if __name__ == '__main__':
    print("\n╔════════════════════════════════════════════════════════════════╗")
    print("║   Integrated Cybersecurity Toolkit v5.0                       ║")
    print("║   Password Cracker + Network Tools + Shodan Integration      ║")
    print("║                                                                ║")
    print("║   Author: Dr. Mohammed Tawfik                                 ║")
    print("║   Email: kmkhol01@gmail.com                                   ║")
    print("╚════════════════════════════════════════════════════════════════╝\n")
    print("✓ Password Cracking: GPU/CPU support, multiple hash algorithms")
    print("✓ Network Tools: Ping diagnostics and connectivity analysis")
    print("✓ Shodan Integration: Device reconnaissance and OSINT")
    print("✓ Modular Architecture: Easy to extend with new tools")
    print("\n⚠️  EDUCATIONAL USE ONLY - Unauthorized use is illegal!\n")
    
    if not SHODAN_AVAILABLE:
        print("⚠️  Note: Shodan library not installed.")
        print("   To enable Shodan features, run: pip install shodan\n")
    
    root = tk.Tk()
    app = CyberSecurityToolkit_GUI(root)
    root.mainloop()
