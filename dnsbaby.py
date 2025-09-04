
import dns.resolver
import sys
import json
import csv
import argparse
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time

class DNSEnumerator:
    def __init__(self, domain, dns_servers=None, timeout=5, threads=10):
        self.domain = self.validate_domain(domain)
        self.timeout = timeout
        self.threads = threads
        self.results = {}
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        if dns_servers:
            self.resolver.nameservers = dns_servers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
            'secure', 'vpn', 'api', 'dev', 'test', 'admin', 'blog'
        ]

    def validate_domain(self, domain):
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        if not domain_pattern.match(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        return domain.lower()

    def query_record_type(self, domain, record_type):
        try:
            answer = self.resolver.resolve(domain, record_type)
            records = []
            for record in answer:
                record_data = {
                    'value': str(record),
                    'ttl': answer.ttl if hasattr(answer, 'ttl') else 'N/A'
                }
                records.append(record_data)
            return records
        except dns.resolver.NXDOMAIN:
            return None  
        except dns.resolver.NoAnswer:
            return [] 
        except dns.exception.Timeout:
            return {'error': 'Timeout'}
        except Exception as e:
            return {'error': str(e)}

    def enumerate_records(self, custom_records=None):
        record_types = custom_records or self.record_types
        
        print(f"\n[-] Enumerating DNS records for: {self.domain}")
        print("=" * 50)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_record = {
                executor.submit(self.query_record_type, self.domain, record_type): record_type
                for record_type in record_types
            }
            
            for future in as_completed(future_to_record):
                record_type = future_to_record[future]
                try:
                    result = future.result()
                    if result is not None:
                        self.results[record_type] = result
                        self.display_records(record_type, result)
                except Exception as e:
                    print(f"[!] Error querying {record_type}: {e}")

    def enumerate_subdomains(self, wordlist=None):
        subdomains = wordlist or self.common_subdomains
        found_subdomains = []
        
        print(f"\n[-] Enumerating subdomains for: {self.domain}")
        print("=" * 50)
        
        def check_subdomain(subdomain):
            fqdn = f"{subdomain}.{self.domain}"
            try:
                answer = self.resolver.resolve(fqdn, 'A')
                return {
                    'subdomain': fqdn,
                    'records': [str(record) for record in answer]
                }
            except:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, subdomain): subdomain
                for subdomain in subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"[+] Found: {result['subdomain']} -> {', '.join(result['records'])}")
        
        self.results['subdomains'] = found_subdomains
        print(f"\[+] Found {len(found_subdomains)} subdomains")

    def display_records(self, record_type, records):
        if isinstance(records, dict) and 'error' in records:
            print(f"[*] {record_type}: {records['error']}")
            return
        
        if not records:
            return
        
        print(f"\n[*] {record_type} Records:")
        for i, record in enumerate(records, 1):
            if isinstance(record, dict):
                ttl_info = f" (TTL: {record['ttl']})" if record.get('ttl') != 'N/A' else ""
                print(f"  {i}. {record['value']}{ttl_info}")
            else:
                print(f"  {i}. {record}")

    def save_results(self, filename, format_type='json'):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if format_type.lower() == 'json':
            filename = f"{filename}_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump({
                    'domain': self.domain,
                    'timestamp': timestamp,
                    'results': self.results
                }, f, indent=2)
        
        elif format_type.lower() == 'csv':
            filename = f"{filename}_{timestamp}.csv"
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Record Type', 'Value', 'TTL'])
                
                for record_type, records in self.results.items():
                    if record_type == 'subdomains':
                        for subdomain in records:
                            for record in subdomain['records']:
                                writer.writerow([subdomain['subdomain'], 'A', record, 'N/A'])
                    elif isinstance(records, list):
                        for record in records:
                            if isinstance(record, dict):
                                writer.writerow([self.domain, record_type, record['value'], record.get('ttl', 'N/A')])
        
        print(f"\n[$] Results saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description='DNS Enumeration Tool')
    parser.add_argument('domain', help='Domain to enumerate')
    parser.add_argument('--dns-servers', nargs='+', help='Custom DNS servers to use')
    parser.add_argument('--records', nargs='+', help='Specific record types to query')
    parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains')
    parser.add_argument('--wordlist', help='Custom subdomain wordlist file')
    parser.add_argument('--save', help='Save results to file (specify filename without extension)')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format for saved results')
    parser.add_argument('--timeout', type=int, default=5, help='DNS query timeout (seconds)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for concurrent queries')
    
    args = parser.parse_args()
    
    try:
        # Initialize DNS enumerator
        dns_enum = DNSEnumerator(
            domain=args.domain,
            dns_servers=args.dns_servers,
            timeout=args.timeout,
            threads=args.threads
        )
        
        # Custom wordlist
        custom_wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, 'r') as f:
                    custom_wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"[-] Wordlist file not found: {args.wordlist}")
                sys.exit(1)
        
        # Perform enumeration
        dns_enum.enumerate_records(args.records)
        if args.subdomains:
            dns_enum.enumerate_subdomains(custom_wordlist)
        if args.save:
            dns_enum.save_results(args.save, args.format)
        
        print(f"\n[+] DNS enumeration completed for {args.domain}")
        
    except ValueError as e:
        print(f"[!] Input error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n[/]  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python3 dnsbaby.py <domain> [options]")
        print("Example: python3 dnsbaby.py example.com --subdomains --save results")
    else:
        main()