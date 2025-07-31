#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
import urllib.parse
import base64
import re
import sys
import os
import io
import locale
from typing import Dict, Any, List, Optional, Union, Tuple

# Set up console encoding for Windows
if sys.platform == 'win32':
    # For Windows console
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if sys.stderr.encoding != 'utf-8':
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    
    # Try to set console output to UTF-8
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCP(65001)
        kernel32.SetConsoleOutputCP(65001)
    except:
        pass

# Set locale for better text handling
try:
    locale.setlocale(locale.LC_ALL, '')
except:
    pass

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_success(message: str) -> None:
    print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")

def print_warning(message: str) -> None:
    print(f"{Colors.YELLOW}⚠ {message}{Colors.ENDC}")

def print_error(message: str) -> None:
    print(f"{Colors.RED}✗ {message}{Colors.ENDC}", file=sys.stderr)

def print_info(message: str) -> None:
    print(f"{Colors.CYAN}ℹ {message}{Colors.ENDC}")

def parse_ss(ss_url: str) -> Optional[Dict[str, Any]]:
    """Parse ShadowSocks URL into Clash config format."""
    try:
        # Remove ss:// prefix
        ss_url = ss_url[5:]
        
        # Extract name if exists
        name = 'SS Proxy'
        if '#' in ss_url:
            parts = ss_url.split('#')
            name = urllib.parse.unquote(parts[1])
            ss_url = parts[0]
        
        # Handle base64 encoded part
        if ':' in ss_url and '@' not in ss_url:
            # Format: method:password@host:port
            b64_part = ss_url.split('@')[0]
            server_part = ss_url.split('@')[1]
            method, password = base64.b64decode(b64_part + '=' * (-len(b64_part) % 4)).decode('utf-8').split(':', 1)
        else:
            # Format: base64(method:password)@host:port
            method_password_b64 = ss_url.split('@')[0]
            server_part = ss_url.split('@')[1]
            method_password = base64.b64decode(method_password_b64 + '=' * (-len(method_password_b64) % 4)).decode('utf-8')
            method, password = method_password.split(':', 1)
        
        # Parse server and port
        server, port = server_part.split(':')
        port = int(port)
        
        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
    except Exception as e:
        print(f"Error parsing SS URL: {e}")
        return None

def parse_vless(vless_url: str) -> Optional[Dict[str, Any]]:
    """Parse VLESS URL into Clash config format."""
    try:
        # Remove vless:// prefix
        vless_url = vless_url[8:]
        
        # Extract name if exists
        name = 'VLESS Proxy'
        if '#' in vless_url:
            parts = vless_url.split('#')
            name = urllib.parse.unquote(parts[1])
            vless_url = parts[0]
        
        # Parse server, port, and user info
        userinfo, serverinfo = vless_url.split('@')
        server, port = serverinfo.split('?')[0].split(':')
        port = int(port)
        
        # Parse query parameters
        query = {}
        if '?' in vless_url:
            query_str = vless_url.split('?', 1)[1]
            if '#' in query_str:
                query_str = query_str.split('#', 1)[0]
            query = dict(urllib.parse.parse_qsl(query_str))
        
        # Build config
        config = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': userinfo,
            'udp': True,
            'skip-cert-verify': True,
            'tls': 'tls' in query.get('security', '').lower(),
            'network': query.get('type', 'tcp')
        }
        
        # Handle transport settings
        if 'security' in query:
            config['tls'] = query['security'].lower() == 'tls'
            if 'reality' in query['security'].lower():
                config['reality-opts'] = {
                    'public-key': query.get('pbk', ''),
                    'short-id': query.get('sid', '')
                }
        
        if 'sni' in query:
            config['servername'] = query['sni']
        
        if 'fp' in query:
            config['client-fingerprint'] = query['fp']
        
        return config
    except Exception as e:
        print(f"Error parsing VLESS URL: {e}")
        return None

def parse_trojan(trojan_url: str) -> Optional[Dict[str, Any]]:
    """Parse Trojan URL into Clash config format."""
    try:
        # Remove trojan:// prefix
        trojan_url = trojan_url[9:]
        
        # Extract name if exists
        name = 'Trojan Proxy'
        if '#' in trojan_url:
            parts = trojan_url.split('#')
            name = urllib.parse.unquote(parts[1])
            trojan_url = parts[0]
        
        # Parse server, port, and password
        password, serverinfo = trojan_url.split('@')
        server, port = serverinfo.split('?')[0].rsplit(':', 1)
        port = int(port)
        
        # Parse query parameters
        query = {}
        if '?' in trojan_url:
            query_str = trojan_url.split('?', 1)[1]
            if '#' in query_str:
                query_str = query_str.split('#', 1)[0]
            query = dict(urllib.parse.parse_qsl(query_str))
        
        # Build config
        config = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'udp': True,
            'skip-cert-verify': query.get('allowInsecure', '1') == '1',
            'sni': query.get('sni', '')
        }
        
        if 'sni' in query:
            config['sni'] = query['sni']
        
        return config
    except Exception as e:
        print(f"Error parsing Trojan URL: {e}")
        return None

def parse_hysteria2(h2_url: str) -> Optional[Dict[str, Any]]:
    """Parse Hysteria2 URL into Clash config format."""
    try:
        # Remove hysteria2:// prefix
        h2_url = h2_url[12:]
        
        # Extract name if exists
        name = 'Hysteria2 Proxy'
        if '#' in h2_url:
            parts = h2_url.split('#')
            name = urllib.parse.unquote(parts[1])
            h2_url = parts[0]
        
        # Parse server, port, and password
        if '@' in h2_url:
            password, serverinfo = h2_url.split('@', 1)
        else:
            password = ''
            serverinfo = h2_url
        
        # Extract server and port
        if '?' in serverinfo:
            server_part = serverinfo.split('?')[0]
        else:
            server_part = serverinfo
        
        # Clean up port number (remove any trailing slashes or other characters)
        if ':' in server_part:
            server, port = server_part.rsplit(':', 1)
            # Remove any non-numeric characters from port
            port = ''.join(filter(str.isdigit, port))
            port = int(port) if port else 443  # Default to 443 if port is empty
        else:
            server = server_part
            port = 443  # Default port
        
        # Parse query parameters
        query = {}
        if '?' in h2_url:
            query_str = h2_url.split('?', 1)[1]
            if '#' in query_str:
                query_str = query_str.split('#', 1)[0]
            query = dict(urllib.parse.parse_qsl(query_str))
        
        # Build config
        config = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'skip-cert-verify': query.get('insecure', '1') == '1',
            'sni': query.get('sni', '')
        }
        
        if 'obfs' in query and query['obfs'] == 'salamander':
            config['obfs'] = 'salamander'
            if 'obfs-password' in query:
                config['obfs-password'] = query['obfs-password']
        
        return config
    except Exception as e:
        print(f"Error parsing Hysteria2 URL: {e}")
        return None

def parse_proxy_url(url: str) -> Optional[Dict[str, Any]]:
    """Parse a proxy URL and return the appropriate config."""
    if url.startswith('ss://'):
        return parse_ss(url)
    elif url.startswith('vless://'):
        return parse_vless(url)
    elif url.startswith('trojan://'):
        return parse_trojan(url)
    elif url.startswith('hysteria2://'):
        return parse_hysteria2(url)
    else:
        print(f"Unsupported proxy type: {url.split('://')[0]}")
        return None

def get_ad_blocking_rules() -> Dict[str, Any]:
    """Return the ad-blocking rule providers and rules."""
    return {
        'rule-providers': {
            'AD': {
                'type': 'http',
                'behavior': 'domain',
                'url': 'https://raw.githubusercontent.com/earoftoast/clash-rules/main/AD.yaml',
                'path': './rules/AD.yaml',
                'interval': 86400
            },
            'EasyList': {
                'type': 'http',
                'behavior': 'domain',
                'url': 'https://raw.githubusercontent.com/earoftoast/clash-rules/main/EasyList.yaml',
                'path': './rules/EasyList.yaml',
                'interval': 86400
            },
            'EasyListChina': {
                'type': 'http',
                'behavior': 'domain',
                'url': 'https://raw.githubusercontent.com/earoftoast/clash-rules/main/EasyListChina.yaml',
                'path': './rules/EasyListChina.yaml',
                'interval': 86400
            },
            'EasyPrivacy': {
                'type': 'http',
                'behavior': 'domain',
                'url': 'https://raw.githubusercontent.com/earoftoast/clash-rules/main/EasyPrivacy.yaml',
                'path': './rules/EasyPrivacy.yaml',
                'interval': 86400
            },
            'ProgramAD': {
                'type': 'http',
                'behavior': 'domain',
                'url': 'https://raw.githubusercontent.com/earoftoast/clash-rules/main/ProgramAD.yaml',
                'path': './rules/ProgramAD.yaml',
                'interval': 86400
            }
        },
        'rules': [
            'RULE-SET,AD,REJECT',
            'RULE-SET,EasyList,REJECT',
            'RULE-SET,EasyListChina,REJECT',
            'RULE-SET,EasyPrivacy,REJECT',
            'RULE-SET,ProgramAD,REJECT',
            # Add more rules after these
            'MATCH,DIRECT'  # Default rule
        ]
    }

def generate_clash_config(proxies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate Clash configuration from a list of proxies."""
    # Filter out None values
    proxies = [p for p in proxies if p is not None]
    
    # Handle duplicate names by appending numbers
    name_count = {}
    for proxy in proxies:
        name = proxy['name']
        if name in name_count:
            name_count[name] += 1
            proxy['name'] = f"{name} {name_count[name]}"
        else:
            name_count[name] = 1
    
    # Get ad-blocking rules
    ad_rules = get_ad_blocking_rules()
    
    # Define proxy groups
    proxy_groups = [
        {
            'name': 'PROXY',
            'type': 'select',
            'proxies': ['DIRECT'] + [p['name'] for p in proxies]
        },
        {
            'name': 'AUTO',
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'proxies': [p['name'] for p in proxies]
        }
    ]
    
    # Define rules
    rules = [
        # Ad-blocking rules (from rule providers)
        'RULE-SET,AD,REJECT',
        'RULE-SET,EasyList,REJECT',
        'RULE-SET,EasyListChina,REJECT',
        'RULE-SET,EasyPrivacy,REJECT',
        'RULE-SET,ProgramAD,REJECT',
        
        # Local network rules
        'DOMAIN-SUFFIX,local,DIRECT',
        'IP-CIDR,127.0.0.0/8,DIRECT',
        'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT',
        'IP-CIDR,172.16.0.0/12,DIRECT',
        'IP-CIDR6,::1/128,DIRECT',
        'IP-CIDR6,fc00::/7,DIRECT',
        
        # Common proxy rules
        'DOMAIN-SUFFIX,google.com,PROXY',
        'DOMAIN-KEYWORD,google,PROXY',
        'DOMAIN-SUFFIX,github.com,PROXY',
        'DOMAIN-SUFFIX,github.io,PROXY',
        'DOMAIN-SUFFIX,githubusercontent.com,PROXY',
        'DOMAIN-SUFFIX,youtube.com,PROXY',
        'DOMAIN-SUFFIX,ytimg.com,PROXY',
        'DOMAIN-SUFFIX,twitter.com,PROXY',
        'DOMAIN-SUFFIX,facebook.com,PROXY',
        'DOMAIN-SUFFIX,instagram.com,PROXY',
        'DOMAIN-SUFFIX,whatsapp.com,PROXY',
        'DOMAIN-SUFFIX,telegram.org,PROXY',
        'DOMAIN-SUFFIX,openai.com,PROXY',
        'DOMAIN-SUFFIX,cloudflare.com,PROXY',
        'DOMAIN-SUFFIX,cloudfront.net,PROXY',
        'DOMAIN-SUFFIX,akamai.net,PROXY',
        'DOMAIN-SUFFIX,akamaiedge.net,PROXY',
        'DOMAIN-SUFFIX,akamaihd.net,PROXY',
        'IP-CIDR,91.108.56.0/22,PROXY',
        'IP-CIDR,91.108.4.0/22,PROXY',
        'IP-CIDR,91.108.8.0/22,PROXY',
        'IP-CIDR,91.108.16.0/22,PROXY',
        'IP-CIDR,91.108.12.0/22,PROXY',
        'IP-CIDR,149.154.160.0/20,PROXY',
        'IP-CIDR,91.105.192.0/23,PROXY',
        'IP-CIDR,91.108.20.0/22,PROXY',
        'GEOIP,CN,DIRECT',
        'MATCH,PROXY'
    ]
    
    # Build final config
    config = {
        'port': 7890,
        'socks-port': 7891,
        'redir-port': 7892,
        'allow-lan': False,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': proxy_groups,
        'rule-providers': ad_rules['rule-providers'],
        'rules': rules
    }
    
    return config

def get_relative_path(path: str) -> str:
    """Convert path to be relative to the script's directory."""
    if os.path.isabs(path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        try:
            # Get the relative path and ensure it's within the script directory
            rel_path = os.path.relpath(os.path.abspath(path), script_dir)
            if rel_path.startswith('..'):
                raise ValueError("Path must be within the script's directory")
            return os.path.join(script_dir, rel_path)
        except (ValueError, Exception):
            raise ValueError("Invalid path: must be within the script's directory")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)

def process_base64(input_file: str, output_file: str, decode: bool = False) -> Tuple[bool, str]:
    """
    Process file with base64 encode/decode.
    Returns: (success: bool, message: str)
    """
    try:
        # Convert to absolute paths relative to script directory
        input_path = get_relative_path(input_file)
        output_path = get_relative_path(output_file)
        
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        with open(input_path, 'rb') as f:
            content = f.read()
            
        if decode:
            # Try to decode as UTF-8 first, then as raw bytes if that fails
            try:
                content = base64.b64decode(content.decode('utf-8'))
            except UnicodeDecodeError:
                content = base64.b64decode(content)
            
            # Try to decode the result as UTF-8 if it's text
            try:
                content = content.decode('utf-8')
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            except UnicodeDecodeError:
                # If it's not UTF-8, write as binary
                with open(output_path, 'wb') as f:
                    f.write(content)
                    
            return True, f"Successfully decoded {input_file} to {output_file}"
        else:
            # Encode to base64
            encoded = base64.b64encode(content).decode('utf-8')
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(encoded)
                
            return True, f"Successfully encoded {input_file} to {output_file}\nOriginal size: {len(content)} bytes, Encoded size: {len(encoded)} bytes"
            
    except Exception as e:
        return False, f"Error processing file: {str(e)}"

def process_clash(input_file: str, output_file: str) -> Tuple[bool, str, List[Tuple[bool, str]]]:
    """
    Convert proxy list to Clash config.
    Returns: (success: bool, message: str, results: List[Tuple[success: bool, message: str]])
    """
    if not os.path.exists(input_file):
        return False, f"Input file not found: {input_file}", []
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except IOError as e:
        return False, f"Failed to read input file: {str(e)}", []
    
    if not urls:
        return False, "Input file is empty", []
    
    # Parse all proxy URLs
    results = []
    proxies = []
    
    for url in urls:
        try:
            proxy = parse_proxy_url(url)
            if proxy:
                proxies.append(proxy)
                results.append((True, f"Success: {url}"))
            else:
                results.append((False, f"Failed to parse: {url}"))
        except Exception as e:
            results.append((False, f"Error parsing '{url}': {str(e)}"))
    
    success_count = sum(1 for r in results if r[0])
    total_count = len(results)
    
    if not proxies:
        return False, f"No valid proxy URLs found in the input file ({success_count}/{total_count} processed)", results
    
    try:
        # Generate Clash config
        config = generate_clash_config(proxies)
        
        # Write to output file
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
            
        success = success_count == total_count
        message = f"Generated Clash config: {output_file} ({success_count}/{total_count} proxies, {total_count - success_count} failed)"
        return success, message, results
        
    except Exception as e:
        return False, f"Failed to generate Clash config: {str(e)}", results

def parse_args():
    """Parse command line arguments."""
    if len(sys.argv) < 2:
        print_info("Available commands:")
        print("  base64 <input_file> to <output_file> [--decode]")
        print("  clash <input_file> to <output_file>")
        print("\nExamples:")
        print("  python sc.py clash input.txt to config.yaml")
        print("  python sc.py base64 file.txt to file.enc")
        print("  python sc.py base64 file.enc to file.txt --decode")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command not in ['base64', 'clash']:
        print_error(f"Incorrect command: {command}")
        print_info("\nAvailable commands: base64, clash")
        sys.exit(1)
    
    try:
        to_index = sys.argv.index('to')
        if to_index == -1 or to_index + 1 >= len(sys.argv):
            print("Error: Missing output file after 'to'")
            sys.exit(1)
            
        input_file = sys.argv[2]
        output_file = sys.argv[to_index + 1]
        
        # Handle optional arguments
        decode = '--decode' in sys.argv
        
        return {
            'command': command,
            'input_file': input_file,
            'output_file': output_file,
            'decode': decode
        }
    except ValueError:
        print("Error: Invalid command format")
        print("Example: python sc.py clash input.txt to output.yaml")
        sys.exit(1)

def show_menu() -> None:
    """Display the interactive menu and handle user input."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    def get_input_path(prompt: str, default: str = '') -> str:
        """Helper function to get a relative path from the user."""
        while True:
            path = input(prompt).strip('"').strip()
            if not path:
                if default:
                    return default
                print_error("路径不能为空")
                continue
                
            try:
                # Convert to absolute path and check if it's within the script directory
                abs_path = os.path.abspath(os.path.join(script_dir, path))
                if not abs_path.startswith(script_dir):
                    print_error("错误: 路径必须在当前项目目录内")
                    continue
                return path
            except Exception as e:
                print_error(f"无效的路径: {str(e)}")
    
    while True:
        print("\n" + "="*50)
        print(f"{Colors.HEADER}{Colors.BOLD}Clash 配置转换工具{Colors.ENDC}")
        print("="*50)
        print(f"{Colors.CYAN}1.{Colors.ENDC} 转换为Clash配置")
        print(f"{Colors.CYAN}2.{Colors.ENDC} Base64编码文件")
        print(f"{Colors.CYAN}3.{Colors.ENDC} Base64解码文件")
        print(f"{Colors.YELLOW}0.{Colors.ENDC} 退出")
        print("="*50)
        print(f"当前项目目录: {script_dir}")
        print("="*50)
        
        choice = input(f"{Colors.BLUE}请选择操作 (0-3): {Colors.ENDC}").strip()
        
        if choice == '1':
            print(f"\n{Colors.HEADER}转换为Clash配置{Colors.ENDC}")
            print("-"*50)
            input_file = get_input_path("输入代理列表文件路径(相对或绝对路径): ")
            default_output = os.path.join("output", "config.yaml") if os.path.exists("output") else "config.yaml"
            output_file = get_input_path(f"输出Clash配置文件路径 [默认为 {default_output}]: ", default_output)
            
            print("\n" + "-"*50)
            print(f"{Colors.CYAN}正在处理...{Colors.ENDC}")
            success, message, _ = process_clash(input_file, output_file)
            if success:
                print_success(message)
            else:
                print_error(message)
                
        elif choice == '2':
            print(f"\n{Colors.HEADER}Base64编码文件{Colors.ENDC}")
            print("-"*50)
            input_file = get_input_path("输入要编码的文件路径(相对或绝对路径): ")
            output_file = get_input_path("输出编码后文件路径(相对或绝对路径): ", f"{input_file}.base64")
            
            print("\n" + "-"*50)
            print(f"{Colors.CYAN}正在编码...{Colors.ENDC}")
            success, message = process_base64(input_file, output_file, decode=False)
            if success:
                print_success(message)
            else:
                print_error(message)
                
        elif choice == '3':
            print(f"\n{Colors.HEADER}Base64解码文件{Colors.ENDC}")
            print("-"*50)
            input_file = get_input_path("输入要解码的文件路径(相对或绝对路径): ")
            output_file = get_input_path("输出解码后文件路径(相对或绝对路径): ")
            
            print("\n" + "-"*50)
            print(f"{Colors.CYAN}正在解码...{Colors.ENDC}")
            success, message = process_base64(input_file, output_file, decode=True)
            if success:
                print_success(message)
            else:
                print_error(message)
                
        elif choice == '0':
            print("\n感谢使用，再见！")
            break
            
        else:
            print_error("无效的选择，请重新输入")
            
        input("\n按回车键继续...")

def main():
    # If no command line arguments provided, show interactive menu
    if len(sys.argv) == 1:
        try:
            show_menu()
            return
        except KeyboardInterrupt:
            print("\n\n操作已取消。")
            return
        except Exception as e:
            print_error(f"发生错误: {str(e)}")
            return
    
    # Otherwise, process command line arguments
    try:
        args = parse_args()
        
        if args['command'] == 'base64':
            if not (args['input_file'] and args['output_file']):
                print_error("Base64操作需要指定输入和输出文件")
                print_info("用法: python sc.py base64 输入文件 to 输出文件 [--decode]")
                sys.exit(1)
                
            success, message = process_base64(args['input_file'], args['output_file'], args['decode'])
            if success:
                print_success(message)
                sys.exit(0)
            else:
                print_error(message)
                sys.exit(1)
                
        elif args['command'] == 'clash':
            if not (args['input_file'] and args['output_file']):
                print_error("Clash配置转换需要指定输入和输出文件")
                print_info("用法: python sc.py clash 输入文件 to 输出文件")
                sys.exit(1)
                
            success, message, results = process_clash(args['input_file'], args['output_file'])
            if success:
                print_success(message)
                sys.exit(0)
            else:
                print_error(message)
                sys.exit(1)
                
    except KeyboardInterrupt:
        print("\n操作已取消。")
        sys.exit(1)
    except Exception as e:
        print_error(f"发生错误: {str(e)}")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
