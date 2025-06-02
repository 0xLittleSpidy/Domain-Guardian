#!/usr/bin/env python3
"""
typoscout - Typosquatting Domain Reconnaissance
"""

import argparse
import asyncio
import aiohttp
import socket
import time
import csv
import sys
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
import threading
from itertools import product
import string
import dns.resolver
import dns.exception

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ProgressBar:
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self.lock = threading.Lock()
        
    def update(self, increment: int = 1):
        with self.lock:
            self.current += increment
            self._display()
    
    def _display(self):
        if self.total == 0:
            return
        
        percentage = (self.current / self.total) * 100
        filled_length = int(50 * self.current // self.total)
        bar = '█' * filled_length + '-' * (50 - filled_length)
        
        elapsed_time = time.time() - self.start_time
        if self.current > 0:
            eta = (elapsed_time / self.current) * (self.total - self.current)
            eta_str = f"ETA: {eta:.1f}s"
        else:
            eta_str = "ETA: --"
        
        sys.stdout.write(f'\r{Colors.CYAN}{self.description}: {Colors.WHITE}[{bar}] {Colors.YELLOW}{percentage:.1f}% {Colors.GREEN}({self.current}/{self.total}) {Colors.BLUE}{eta_str}{Colors.END}')
        sys.stdout.flush()
    
    def finish(self):
        self.current = self.total
        self._display()
        print()

class TyposquatGenerator:
    """Generate typosquat variations of a domain"""
    
    @staticmethod
    def generate_typosquats(domain: str) -> List[str]:
        """Generate various typosquat variations"""
        typosquats = set()
        
        if '.' not in domain:
            return []
            
        name, tld = domain.rsplit('.', 1)
        
        # Character omission
        for i in range(len(name)):
            typosquats.add(name[:i] + name[i+1:] + '.' + tld)
        
        # Character repetition
        for i in range(len(name)):
            typosquats.add(name[:i] + name[i] + name[i:] + '.' + tld)
        
        # Character replacement (common typos)
        keyboard_map = {
            'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'erfcsx', 'e': 'wrdsf',
            'f': 'rtgvcd', 'g': 'tyhbvf', 'h': 'yugjnb', 'i': 'uojkl', 'j': 'ikmnhu',
            'k': 'olmji', 'l': 'pkj', 'm': 'nkj', 'n': 'bmhj', 'o': 'iplk',
            'p': 'ol', 'q': 'wa', 'r': 'etdf', 's': 'awedxz', 't': 'ryfg',
            'u': 'yihj', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tugh',
            'z': 'asx'
        }
        
        for i, char in enumerate(name.lower()):
            if char in keyboard_map:
                for replacement in keyboard_map[char]:
                    new_name = name[:i] + replacement + name[i+1:]
                    typosquats.add(new_name + '.' + tld)
        
        # Character transposition
        for i in range(len(name) - 1):
            new_name = name[:i] + name[i+1] + name[i] + name[i+2:]
            typosquats.add(new_name + '.' + tld)
        
        # Character insertion
        for i in range(len(name) + 1):
            for char in string.ascii_lowercase:
                new_name = name[:i] + char + name[i:]
                typosquats.add(new_name + '.' + tld)
        
        # Common TLD variations
        common_tlds = ['com', 'net', 'org', 'info', 'biz', 'co', 'io', 'me', 'tv']
        for new_tld in common_tlds:
            if new_tld != tld:
                typosquats.add(name + '.' + new_tld)
        
        # Remove original domain and invalid entries
        typosquats.discard(domain)
        typosquats = [t for t in typosquats if t and len(t.split('.')[0]) > 0]
        
        return list(typosquats)

class DomainChecker:
    """Check domain availability and DNS information"""
    
    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.semaphore = asyncio.Semaphore(requests_per_second)
        self.session = None
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
        timeout = aiohttp.ClientTimeout(total=10)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def check_domain(self, domain: str) -> Dict[str, str]:
        """Check if domain is registered and get IP information"""
        async with self.semaphore:
            result = {
                'domain': domain,
                'status': 'Unknown',
                'ip_addresses': '',
                'nameservers': '',
                'registrar': ''
            }
            
            try:
                # DNS resolution check
                loop = asyncio.get_event_loop()
                
                # Check A records
                try:
                    with ThreadPoolExecutor() as executor:
                        a_records = await loop.run_in_executor(
                            executor, self._resolve_dns, domain, 'A'
                        )
                    if a_records:
                        result['ip_addresses'] = ', '.join(a_records)
                        result['status'] = 'Registered'
                except Exception:
                    pass
                
                # Check NS records
                try:
                    with ThreadPoolExecutor() as executor:
                        ns_records = await loop.run_in_executor(
                            executor, self._resolve_dns, domain, 'NS'
                        )
                    if ns_records:
                        result['nameservers'] = ', '.join(ns_records)
                        if result['status'] == 'Unknown':
                            result['status'] = 'Registered'
                except Exception:
                    pass
                
                # If no DNS records found, likely available
                if result['status'] == 'Unknown':
                    result['status'] = 'Available'
                
                # Rate limiting
                await asyncio.sleep(1.0 / self.requests_per_second)
                
            except Exception as e:
                result['status'] = f'Error: {str(e)}'
            
            return result
    
    def _resolve_dns(self, domain: str, record_type: str) -> List[str]:
        """Resolve DNS records synchronously"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception:
            return []

class DomainGuardian:
    """Main application class"""
    
    def __init__(self):
        self.start_time = None
        self.results = []
    
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description='TypoScout - Typosquatting Domain Reconnaissance',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='Examples:\n'
                   '  python typoscout.py -d example.com\n'
                   '  python typoscout.py -df domains.txt -o results.csv\n'
                   '  python typoscout.py -d example.com -r 5 --debug'
        )
        
        parser.add_argument('-d', '--domain', 
                          help='Single domain to check for typosquats')
        
        parser.add_argument('-df', '--domain-file', 
                          help='File containing multiple domains (one per line)')
        
        parser.add_argument('-o', '--output', 
                          help='Output CSV file to store results')
        
        parser.add_argument('-r', '--requests-per-second', 
                          type=int, default=10,
                          help='Number of requests per second (default: 10)')
        
        parser.add_argument('-de', '--debug', 
                          action='store_true',
                          help='Enable debug mode to show detailed logs')
        
        return parser.parse_args()
    
    def load_domains(self, args: argparse.Namespace) -> List[str]:
        """Load domains from command line or file"""
        domains = []
        
        if args.domain:
            domains.append(args.domain.strip().lower())
        
        if args.domain_file:
            try:
                with open(args.domain_file, 'r') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            domains.append(domain)
            except FileNotFoundError:
                print(f"{Colors.RED}Error: File '{args.domain_file}' not found{Colors.END}")
                sys.exit(1)
        
        if not domains:
            print(f"{Colors.RED}Error: No domains provided. Use -d or -df option{Colors.END}")
            sys.exit(1)
        
        return domains
    
    async def process_domains(self, domains: List[str], args: argparse.Namespace):
        """Process all domains and generate typosquats"""
        all_typosquats = []
        
        # Generate typosquats for all domains
        print(f"{Colors.BLUE}Generating typosquats for {len(domains)} domain(s)...{Colors.END}")
        for domain in domains:
            typosquats = TyposquatGenerator.generate_typosquats(domain)
            all_typosquats.extend(typosquats)
            print(f"{Colors.GREEN}Generated {len(typosquats)} typosquats for {domain}{Colors.END}")
        
        # Remove duplicates
        all_typosquats = list(set(all_typosquats))
        total_domains = len(all_typosquats)
        
        print(f"{Colors.YELLOW}Total unique typosquats to check: {total_domains}{Colors.END}")
        
        if total_domains == 0:
            print(f"{Colors.RED}No typosquats generated{Colors.END}")
            return
        
        # Initialize progress bar
        progress = None
        if not args.debug:
            progress = ProgressBar(total_domains, "Checking domains")
        
        # Check domains
        async with DomainChecker(args.requests_per_second) as checker:
            tasks = []
            for domain in all_typosquats:
                task = self._check_domain_with_progress(checker, domain, progress, args.debug)
                tasks.append(task)
            
            # Execute with controlled concurrency
            semaphore = asyncio.Semaphore(args.requests_per_second)
            
            async def bounded_check(task):
                async with semaphore:
                    return await task
            
            bounded_tasks = [bounded_check(task) for task in tasks]
            self.results = await asyncio.gather(*bounded_tasks)
        
        if progress:
            progress.finish()
    
    async def _check_domain_with_progress(self, checker: DomainChecker, domain: str, 
                                        progress: Optional[ProgressBar], debug: bool) -> Dict[str, str]:
        """Check domain and update progress"""
        result = await checker.check_domain(domain)
        
        if debug:
            status_color = Colors.GREEN if result['status'] == 'Available' else Colors.RED
            print(f"{result['domain']},{result['status']},{result['ip_addresses']}")
        
        if progress:
            progress.update()
        
        return result
    
    def display_results(self, args: argparse.Namespace):
        """Display results on screen"""
        if not self.results:
            return
        
        if args.debug:
            return  # Already displayed during processing
        
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Results Summary:{Colors.END}")
        
        available_count = sum(1 for r in self.results if r['status'] == 'Available')
        registered_count = sum(1 for r in self.results if r['status'] == 'Registered')
        error_count = sum(1 for r in self.results if r['status'].startswith('Error'))
        
        print(f"{Colors.GREEN}Available domains: {available_count}{Colors.END}")
        print(f"{Colors.RED}Registered domains: {registered_count}{Colors.END}")
        print(f"{Colors.YELLOW}Errors: {error_count}{Colors.END}")
        
        # Show sample of available domains
        available_domains = [r for r in self.results if r['status'] == 'Available']
        if available_domains:
            print(f"\n{Colors.BOLD}Sample Available Domains:{Colors.END}")
            for domain in available_domains[:10]:  # Show first 10
                print(f"{Colors.GREEN}  {domain['domain']}{Colors.END}")
            
            if len(available_domains) > 10:
                print(f"{Colors.CYAN}  ... and {len(available_domains) - 10} more{Colors.END}")
        
        # Show registered domains with IPs
        registered_domains = [r for r in self.results if r['status'] == 'Registered' and r['ip_addresses']]
        if registered_domains:
            print(f"\n{Colors.BOLD}Registered Domains with IPs:{Colors.END}")
            for domain in registered_domains[:5]:  # Show first 5
                print(f"{Colors.RED}  {domain['domain']} -> {domain['ip_addresses']}{Colors.END}")
            
            if len(registered_domains) > 5:
                print(f"{Colors.CYAN}  ... and {len(registered_domains) - 5} more{Colors.END}")
    
    def save_results(self, output_file: str):
        """Save results to CSV file"""
        if not self.results:
            return
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['domain', 'status', 'ip_addresses', 'nameservers', 'registrar']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for result in self.results:
                    writer.writerow(result)
            
            print(f"{Colors.GREEN}Results saved to {output_file}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}Error saving to file: {e}{Colors.END}")
    
    def check_dependencies(self):
        """Check if required packages are available"""
        required_packages = ['aiohttp', 'dnspython']
        missing_packages = []
        
        for package in required_packages:
            try:
                if package == 'dnspython':
                    import dns.resolver
                else:
                    __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"{Colors.RED}Missing required packages: {', '.join(missing_packages)}{Colors.END}")
            print(f"{Colors.YELLOW}Install with: pip install {' '.join(missing_packages)}{Colors.END}")
            sys.exit(1)
    
    async def run(self):
        """Main execution function"""
        print(f"{Colors.BOLD}{Colors.BLUE}Domain Guardian - Defensive Typosquat Detection Tool{Colors.END}")
        print(f"{Colors.CYAN}Brand Protection & Cybersecurity Research Tool{Colors.END}\n")
        
        # Check dependencies
        self.check_dependencies()
        
        # Parse arguments
        args = self.parse_arguments()
        
        # Show help if no arguments
        if len(sys.argv) == 1:
            parser = argparse.ArgumentParser()
            parser.print_help()
            return
        
        # Load domains
        domains = self.load_domains(args)
        
        # Show debug header
        if args.debug:
            print(f"{Colors.BOLD}Domain,Status,IP_Addresses{Colors.END}")
        
        # Start timing
        self.start_time = time.time()
        
        # Process domains
        await self.process_domains(domains, args)
        
        # Calculate execution time
        execution_time = time.time() - self.start_time
        
        # Display results
        self.display_results(args)
        
        # Save results if requested
        if args.output:
            self.save_results(args.output)
        
        # Show execution time
        print(f"\n{Colors.MAGENTA}Execution time: {execution_time:.2f} seconds{Colors.END}")
        print(f"{Colors.MAGENTA}Domains checked: {len(self.results)}{Colors.END}")
        if execution_time > 0:
            rate = len(self.results) / execution_time
            print(f"{Colors.MAGENTA}Average rate: {rate:.2f} domains/second{Colors.END}")

def main():
    """Entry point"""
    try:
        app = DomainGuardian()
        asyncio.run(app.run())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation cancelled by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Unexpected error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
