from curl_cffi import requests
from fake_useragent import FakeUserAgent
from datetime import datetime
from colorama import *
import asyncio, base64, json, os, pytz, logging, random, hashlib, secrets, string

wib = pytz.timezone('Asia/Jakarta')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class OptimaiSetup:
    def __init__(self) -> None:
        self.USER_AGENT = FakeUserAgent().random
        self.BASE_API = "https://node.optimai.network"
        self.PAGE_URL = "https://node.optimai.network/login"
        # Try different possible site keys - these are common Turnstile patterns
        self.SITE_KEYS = [
            "0x4AAAAAAA4YPKMKTNJPEShE",  # Original guess
            "0x4AAAAAAABkMYinukNVgyDn",  # Common pattern
            "0x4AAAAAAADkMYinukNVgyDn",  # Alternative
            "0x4AAAAAAA4YPKMKTNJPEShe",  # Case variation
        ]
        self.CAPTCHA_KEY = None
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://node.optimai.network",
            "Referer": "https://node.optimai.network/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.USER_AGENT
        }
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.passwords = {}
        self.captcha_tokens = {}

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}{message}",
            flush=True
        )

    def welcome(self):
        print(f"""
{Fore.CYAN + Style.BRIGHT}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  {Fore.YELLOW + Style.BRIGHT}🔧 OPTIMAI NETWORK - TOKEN SETUP WIZARD 🔧{Fore.CYAN + Style.BRIGHT}                  ║
║                                                                  ║
║  {Fore.GREEN + Style.BRIGHT}🚀 Advanced Multi-Account Token Generator 🚀{Fore.CYAN + Style.BRIGHT}                ║
║                                                                  ║
║  {Fore.MAGENTA + Style.BRIGHT}⚡ Features:{Fore.CYAN + Style.BRIGHT}                                                ║
║    {Fore.WHITE + Style.BRIGHT}🔐 Email/Password Authentication{Fore.CYAN + Style.BRIGHT}                           ║
║    {Fore.WHITE + Style.BRIGHT}🚀 Parallel Processing (UP TO 15x faster!){Fore.CYAN + Style.BRIGHT}                ║
║    {Fore.WHITE + Style.BRIGHT}⏱️ Smart Random Delays (0.1-0.8s){Fore.CYAN + Style.BRIGHT}                        ║
║    {Fore.WHITE + Style.BRIGHT}🌐 Multi-Proxy Support{Fore.CYAN + Style.BRIGHT}                                    ║
║    {Fore.WHITE + Style.BRIGHT}🛡️ Smart Error Recovery{Fore.CYAN + Style.BRIGHT}                                   ║
║    {Fore.WHITE + Style.BRIGHT}💾 Auto Token Management{Fore.CYAN + Style.BRIGHT}                                  ║
║                                                                  ║
║  {Fore.BLUE + Style.BRIGHT}👨‍💻 Enhanced for OptimAi Network{Fore.CYAN + Style.BRIGHT}                             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW + Style.BRIGHT}💡 TIP: Run this setup first, then use bot.py to start farming! 💡{Style.RESET_ALL}
        """)

    def format_seconds(self, seconds):
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
    def load_accounts(self):
        filename = "accounts.json"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED}File {filename} Not Found.{Style.RESET_ALL}")
                return []

            with open(filename, 'r') as file:
                data = json.load(file)
                if isinstance(data, list):
                    return data
                return []
        except json.JSONDecodeError:
            return []
        
    def is_template_account(self, account):
        """Check if an account entry is a template/placeholder"""
        refresh_token = account.get("refreshToken", "")
        register_payload = account.get("registerPayload", "")
        uptime_payload = account.get("uptimePayload", "")
        
        # Check for template token patterns
        template_patterns = [
            "your_opai_refresh_token", "your_register_payload", "your_uptime_payload",
            "SAMPLE_", "YOUR_", "PLACEHOLDER", "TOKEN_HERE"
        ]
        
        # Check token patterns
        for pattern in template_patterns:
            if pattern in refresh_token or pattern in register_payload or pattern in uptime_payload:
                return True
                
        return False

    def save_accounts(self, new_accounts):
        filename = "accounts.json"
        try:
            existing_accounts = []
            
            # Try to load existing tokens, but handle invalid JSON gracefully
            if os.path.exists(filename) and os.path.getsize(filename) > 0:
                try:
                    with open(filename, 'r') as file:
                        existing_accounts = json.load(file)
                        if not isinstance(existing_accounts, list):
                            existing_accounts = []
                except json.JSONDecodeError:
                    self.log(f"{Fore.YELLOW + Style.BRIGHT}⚠️ accounts.json contains invalid JSON, creating new file{Style.RESET_ALL}")
                    existing_accounts = []
                except Exception as e:
                    self.log(f"{Fore.YELLOW + Style.BRIGHT}⚠️ Could not read accounts.json: {e}, creating new file{Style.RESET_ALL}")
                    existing_accounts = []

            # Filter out template/placeholder accounts from existing accounts
            real_existing_accounts = [acc for acc in existing_accounts if not self.is_template_account(acc)]
            
            # Log if we removed template accounts
            removed_count = len(existing_accounts) - len(real_existing_accounts)
            if removed_count > 0:
                self.log(f"{Fore.YELLOW + Style.BRIGHT}🧹 Removed {removed_count} template account(s) from accounts.json{Style.RESET_ALL}")

            # Merge real existing accounts with new accounts using user_id as unique key
            account_dict = {}
            
            # Process existing accounts - extract user_id from refresh token
            for acc in real_existing_accounts:
                user_id = self.extract_user_id_from_token(acc["refreshToken"])
                if user_id and user_id != "default_user":
                    account_dict[user_id] = acc
                else:
                    # Fallback to refresh token if user_id extraction fails
                    account_dict[acc["refreshToken"]] = acc

            # Process new accounts - they will overwrite existing ones with same user_id
            for new_acc in new_accounts:
                user_id = self.extract_user_id_from_token(new_acc["refreshToken"])
                if user_id and user_id != "default_user":
                    if user_id in account_dict:
                        self.log(f"{Fore.YELLOW + Style.BRIGHT}🔄 Updating existing account for user_id: {user_id[:8]}...{Style.RESET_ALL}")
                    account_dict[user_id] = new_acc
                else:
                    # Fallback to refresh token if user_id extraction fails
                    account_dict[new_acc["refreshToken"]] = new_acc

            updated_accounts = list(account_dict.values())

            # Save to file
            with open(filename, 'w') as file:
                json.dump(updated_accounts, file, indent=4)
                
            total_accounts = len(updated_accounts)
            duplicates_removed = len(real_existing_accounts) + len(new_accounts) - total_accounts
            if duplicates_removed > 0:
                self.log(f"{Fore.GREEN + Style.BRIGHT}🧹 Removed {duplicates_removed} duplicate account(s){Style.RESET_ALL}")
            self.log(f"{Fore.GREEN + Style.BRIGHT}💾 Successfully saved {len(new_accounts)} new account(s) to {filename} (Total: {total_accounts}){Style.RESET_ALL}")
            return True

        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}❌ Failed to save accounts: {e}{Style.RESET_ALL}")
            return False
        
    def load_login_accounts(self):
        filename = "login_accounts.json"
        try:
            if not os.path.exists(filename):
                # Create template file
                template = [
                    {
                        "Email": "your_email_1@example.com",
                        "Password": "your_password_1"
                    },
                    {
                        "Email": "your_email_2@example.com", 
                        "Password": "your_password_2"
                    }
                ]
                with open(filename, 'w') as file:
                    json.dump(template, file, indent=4)
                self.log(f"{Fore.YELLOW + Style.BRIGHT}Created template {filename}. Please fill in your email/password and run again.{Style.RESET_ALL}")
                return []

            with open(filename, 'r') as file:
                data = json.load(file)
                if isinstance(data, list):
                    # Filter out template accounts
                    real_accounts = []
                    for account in data:
                        email = account.get("Email", "").lower()
                        if not any(pattern in email for pattern in ["your_email", "example.com", "@example"]):
                            real_accounts.append(account)
                    return real_accounts
                return []
        except json.JSONDecodeError:
            return []

    async def load_proxies(self, use_proxy_choice: int):
        filename = "proxy.txt"
        try:
            if use_proxy_choice == 1:
                response = await asyncio.to_thread(requests.get, "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt")
                response.raise_for_status()
                content = response.text
                with open(filename, 'w') as f:
                    f.write(content)
                self.proxies = [line.strip() for line in content.splitlines() if line.strip()]
            else:
                if not os.path.exists(filename):
                    self.log(f"{Fore.RED + Style.BRIGHT}File {filename} Not Found.{Style.RESET_ALL}")
                    return
                with open(filename, 'r') as f:
                    self.proxies = [line.strip() for line in f.read().splitlines() if line.strip()]
            
            if not self.proxies:
                self.log(f"{Fore.RED + Style.BRIGHT}No Proxies Found.{Style.RESET_ALL}")
                return

            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Proxies Total  : {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(self.proxies)}{Style.RESET_ALL}"
            )
        
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Failed To Load Proxies: {e}{Style.RESET_ALL}")
            self.proxies = []

    def check_proxy_schemes(self, proxies):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxies.startswith(scheme) for scheme in schemes):
            return proxies
        return f"http://{proxies}"

    def get_next_proxy_for_account(self, email):
        if email not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[email] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.account_proxies[email]

    def rotate_proxy_for_account(self, email):
        if not self.proxies:
            return None
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[email] = proxy
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy
    
    def mask_account(self, account):
        if '@' in account:
            local, domain = account.split('@', 1)
            mask_account = local[:3] + '*' * 3 + local[-3:]
            return f"{mask_account}@{domain}"

    def generate_pkce_challenge(self):
        """Generate PKCE code_verifier and code_challenge for OAuth 2.0"""
        # Generate a cryptographically secure random string for code_verifier
        code_verifier = ''.join(secrets.choice(string.ascii_letters + string.digits + '-._~') for _ in range(128))
        
        # Create code_challenge using SHA256 hash of code_verifier
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge

    async def exchange_oauth_code(self, auth_code: str, code_verifier: str, proxy=None):
        """Exchange OAuth authorization code for access and refresh tokens"""
        
        # Use the exact working endpoint and format
        url = "https://api.optimai.network/auth/token"
        
        # Match the exact working request format
        data = {
            "code": auth_code,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code"
        }
        
        # Match the exact working headers
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "Origin": "https://node.optimai.network",
            "Referer": "https://node.optimai.network/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": self.USER_AGENT
        }
        
        try:
            self.log(f"{Fore.YELLOW + Style.BRIGHT}Exchanging OAuth code for tokens...{Style.RESET_ALL}")
            
            response = await asyncio.to_thread(
                requests.post,
                url=url,
                headers=headers,
                json=data,
                proxy=proxy,
                timeout=60,
                impersonate="chrome110",
                verify=False
            )
            
            self.log(f"{Fore.CYAN + Style.BRIGHT}Token exchange response status: {response.status_code}{Style.RESET_ALL}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"{Fore.BLUE + Style.BRIGHT}Token exchange response: {result}{Style.RESET_ALL}")
                
                # Extract tokens from the exact response format
                access_token = result.get("access_token")
                refresh_token = result.get("refresh_token")
                
                if refresh_token:
                    self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully exchanged OAuth code for tokens{Style.RESET_ALL}")
                    return access_token, refresh_token
                else:
                    self.log(f"{Fore.YELLOW + Style.BRIGHT}Token exchange returned 200 but no refresh token found{Style.RESET_ALL}")
                    return None, None
            else:
                try:
                    error_detail = response.json()
                    self.log(f"{Fore.RED + Style.BRIGHT}OAuth token exchange failed ({response.status_code}): {error_detail}{Style.RESET_ALL}")
                except:
                    self.log(f"{Fore.RED + Style.BRIGHT}OAuth token exchange failed: {response.status_code} - {response.text[:200]}{Style.RESET_ALL}")
                
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Error during OAuth token exchange: {e}{Style.RESET_ALL}")
        
        return None, None

    def extract_user_id_from_token(self, token):
        """Extract user_id from JWT token payload"""
        try:
            import base64
            # JWT format: header.payload.signature
            parts = token.split('.')
            if len(parts) >= 2:
                # Decode the payload (add padding if needed)
                payload = parts[1]
                # Add padding if needed
                payload += '=' * (4 - len(payload) % 4)
                decoded = base64.b64decode(payload).decode('utf-8')
                payload_data = json.loads(decoded)
                user_id = payload_data.get('userId') or payload_data.get('sub')
                return user_id
        except Exception as e:
            self.log(f"{Fore.YELLOW + Style.BRIGHT}Could not extract user_id from token: {e}{Style.RESET_ALL}")
        return "default_user"

    def print_question(self):
        while True:
            try:
                print(f"{Fore.WHITE + Style.BRIGHT}1. Run With Monosans Proxy{Style.RESET_ALL}")
                print(f"{Fore.WHITE + Style.BRIGHT}2. Run With Private Proxy{Style.RESET_ALL}")
                print(f"{Fore.WHITE + Style.BRIGHT}3. Run Without Proxy{Style.RESET_ALL}")
                choose = int(input(f"{Fore.BLUE + Style.BRIGHT}Choose [1/2/3] -> {Style.RESET_ALL}").strip())

                if choose in [1, 2, 3]:
                    proxy_type = (
                        "With Monosans" if choose == 1 else 
                        "With Private" if choose == 2 else 
                        "Without"
                    )
                    print(f"{Fore.GREEN + Style.BRIGHT}Run {proxy_type} Proxy Selected.{Style.RESET_ALL}")
                    return choose
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter either 1, 2 or 3.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1, 2 or 3).{Style.RESET_ALL}")

    def print_processing_question(self):
        while True:
            try:
                print(f"\n{Fore.WHITE + Style.BRIGHT}Processing Mode:{Style.RESET_ALL}")
                print(f"{Fore.WHITE + Style.BRIGHT}1. Sequential (Original - Most Reliable, 1 at a time){Style.RESET_ALL}")
                print(f"{Fore.WHITE + Style.BRIGHT}2. Parallel (🚀 UP TO 15x FASTER! Random delays 0.1-0.8s){Style.RESET_ALL}")
                choose = int(input(f"{Fore.BLUE + Style.BRIGHT}Choose [1/2] -> {Style.RESET_ALL}").strip())

                if choose in [1, 2]:
                    processing_type = "Sequential" if choose == 1 else "Parallel"
                    print(f"{Fore.GREEN + Style.BRIGHT}{processing_type} Processing Selected.{Style.RESET_ALL}")
                    return choose
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter either 1 or 2.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1 or 2).{Style.RESET_ALL}")

    # Payload generation functions (Python implementation of generate_payload.js)
    def fibonacci_mod(self, n):
        """Calculate fibonacci number mod 20 - EXACT match to JavaScript Ts()"""
        t, i = 0, 1
        for s in range(n):
            t, i = i, t + i
        return t % 20

    def transform_bs(self, text):
        """Apply Bs transformation - EXACT match to JavaScript Bs()"""
        return ''.join(chr(ord(char) + self.fibonacci_mod(i)) for i, char in enumerate(text))

    def transform_rs(self, text):
        """Apply Rs transformation - EXACT match to JavaScript Rs()"""
        return ''.join(chr((ord(char) ^ (i % 256)) & 255) for i, char in enumerate(text))

    def transform_ss(self, text):
        """Apply Ss transformation - EXACT match to JavaScript Ss()"""
        chars = list(text)
        for i in range(0, len(chars) - 1, 2):
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
        return ''.join(chars)

    def generate_payload(self, data):
        """Generate payload using the same logic as generate_payload.js"""
        json_str = json.dumps(data, separators=(',', ':'))  # Compact JSON without spaces to match JS
        transformed = self.transform_bs(json_str)
        transformed = self.transform_rs(transformed)
        transformed = self.transform_ss(transformed)
        return base64.b64encode(transformed.encode()).decode()

    def create_register_payload(self, user_id, timestamp):
        """Create register payload"""
        return {
            "user_id": user_id,
            "device_info": {
                "cpu_cores": 1,
                "memory_gb": 0,
                "screen_width_px": 375,
                "screen_height_px": 600,
                "color_depth": 30,
                "scale_factor": 1,
                "browser_name": "chrome",
                "device_type": "extension",
                "language": "id-ID",
                "timezone": "Asia/Jakarta"
            },
            "browser_name": "chrome",
            "device_type": "extension",
            "timestamp": timestamp
        }

    def create_uptime_payload(self, user_id, device_id, timestamp):
        """Create uptime payload"""
        return {
            "duration": 600000,
            "user_id": user_id,
            "device_id": device_id,
            "device_type": "telegram",
            "timestamp": timestamp
        }

    async def auth_login(self, email: str, password: str, proxy=None, retries=3):
        """Login to OptimAi and get refresh token"""
        
        self.log(f"{Fore.CYAN + Style.BRIGHT}🔑 Attempting login for {self.mask_account(email)}{Style.RESET_ALL}")
        
        # First try login without captcha to see if it's always required
        self.log(f"{Fore.YELLOW + Style.BRIGHT}Testing if captcha is required...{Style.RESET_ALL}")
        test_result = await self.test_login_without_captcha(email, password, proxy)
        if test_result:
            return test_result  # Login succeeded without captcha!
        
        # If captcha is required, solve it
        proxy = self.get_next_proxy_for_account(email) if proxy else None
        captcha_solved = await self.solve_cf_turnstile(email, proxy)
        if not captcha_solved:
            self.log(f"{Fore.RED + Style.BRIGHT}Failed to solve captcha for {self.mask_account(email)}{Style.RESET_ALL}")
            return None, None
        
        # Get the solved captcha token
        turnstile_token = self.captcha_tokens.get(email, "")
        
        # Use the correct signin endpoint
        url = "https://api.optimai.network/auth/signin"
        
        for attempt in range(retries):
            try:
                # Add random delay before each login attempt
                login_delay = random.uniform(0.2, 0.8)
                await asyncio.sleep(login_delay)
                
                # Generate PKCE parameters for OAuth 2.0
                code_verifier, code_challenge = self.generate_pkce_challenge()
                
                # Try different data formats and field names with PKCE and turnstile
                json_data_variants = [
                    {
                        "email": email,
                        "password": password,
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                        "turnstile_token": turnstile_token
                    },
                    {
                        "email": email,
                        "password": password,
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                        "turnstile_token": turnstile_token,
                        "remember": False
                    },
                    {
                        "email": email,
                        "password": password,
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                        "turnstile_token": turnstile_token,
                        "client_id": "optimai-web",
                        "response_type": "code"
                    }
                ]
                
                # Enhanced headers to match browser requests
                headers_json = {
                    **self.headers,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/plain, */*",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache"
                }
                
                # Try each data variant
                for variant_idx, json_data in enumerate(json_data_variants):
                    if variant_idx > 0:
                        self.log(f"{Fore.YELLOW + Style.BRIGHT}Trying data variant {variant_idx + 1}: {list(json_data.keys())}{Style.RESET_ALL}")
                    
                    response = await asyncio.to_thread(
                        requests.post, 
                        url=url, 
                        headers=headers_json, 
                        json=json_data,
                        proxy=proxy, 
                        timeout=60, 
                        impersonate="chrome110", 
                        verify=False
                    )
                    
                    self.log(f"{Fore.CYAN + Style.BRIGHT}Login response status for {self.mask_account(email)}: {response.status_code}{Style.RESET_ALL}")
                    
                    # Debug: Print response content for 400 errors
                    if response.status_code == 400:
                        try:
                            error_detail = response.json()
                            self.log(f"{Fore.RED + Style.BRIGHT}400 Error details: {error_detail}{Style.RESET_ALL}")
                        except:
                            self.log(f"{Fore.RED + Style.BRIGHT}400 Error response: {response.text[:200]}{Style.RESET_ALL}")
                    
                    if response.status_code == 200:
                        result = response.json()
                        self.log(f"{Fore.BLUE + Style.BRIGHT}Login success response: {result}{Style.RESET_ALL}")
                        
                        if result.get("success") or "refresh_token" in result or "refreshToken" in result:
                            # Extract refresh token (could be in different keys)
                            refresh_token = result.get("refresh_token") or result.get("refreshToken")
                            access_token = result.get("access_token") or result.get("accessToken")
                            
                            if refresh_token:
                                self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully logged in {self.mask_account(email)}{Style.RESET_ALL}")
                                return access_token, refresh_token
                            else:
                                self.log(f"{Fore.RED + Style.BRIGHT}Missing refresh token in login response for {self.mask_account(email)}{Style.RESET_ALL}")
                                continue
                        elif "code" in result or "authorization_code" in result:
                            # OAuth flow - we got an authorization code, need to exchange it for tokens
                            auth_code = result.get("code") or result.get("authorization_code")
                            self.log(f"{Fore.YELLOW + Style.BRIGHT}Got OAuth code: {auth_code}, exchanging for tokens...{Style.RESET_ALL}")
                            
                            # Exchange code for tokens
                            token_response = await self.exchange_oauth_code(auth_code, code_verifier, proxy)
                            if token_response:
                                access_token, refresh_token = token_response
                                if access_token and refresh_token:
                                    self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully logged in via OAuth {self.mask_account(email)}{Style.RESET_ALL}")
                                    return access_token, refresh_token
                                else:
                                    self.log(f"{Fore.RED + Style.BRIGHT}Missing tokens in OAuth exchange for {self.mask_account(email)}{Style.RESET_ALL}")
                                    continue
                        else:
                            self.log(f"{Fore.RED + Style.BRIGHT}Login failed for {self.mask_account(email)}: {result.get('message', result)}{Style.RESET_ALL}")
                            # If this variant failed, try the next one
                            continue
                    elif response.status_code == 401:
                        self.log(f"{Fore.RED + Style.BRIGHT}Invalid credentials for {self.mask_account(email)}{Style.RESET_ALL}")
                        break  # No point trying other variants with wrong credentials
                    elif response.status_code == 403:
                        self.log(f"{Fore.RED + Style.BRIGHT}Cloudflare blocked request for {self.mask_account(email)} - trying different approach{Style.RESET_ALL}")
                        continue  # Try next variant
                    elif response.status_code == 404:
                        self.log(f"{Fore.RED + Style.BRIGHT}Login endpoint not found for {self.mask_account(email)} - API may have changed{Style.RESET_ALL}")
                        break  # Endpoint is wrong, no point trying variants
                    elif response.status_code == 405:
                        self.log(f"{Fore.YELLOW + Style.BRIGHT}Method not allowed - trying form data for {self.mask_account(email)}{Style.RESET_ALL}")
                        
                        # Try with form data if JSON fails with 405
                        headers_form = {
                            **self.headers,
                            "Content-Type": "application/x-www-form-urlencoded"
                        }
                        
                        form_data = {
                            "email": email,
                            "password": password
                        }
                        
                        response_form = await asyncio.to_thread(
                            requests.post, 
                            url=url, 
                            headers=headers_form, 
                            data=form_data,
                            proxy=proxy, 
                            timeout=60, 
                            impersonate="chrome110", 
                            verify=False
                        )
                        
                        if response_form.status_code == 200:
                            result = response_form.json()
                            if result.get("success") or "refresh_token" in result or "refreshToken" in result:
                                refresh_token = result.get("refresh_token") or result.get("refreshToken")
                                access_token = result.get("access_token") or result.get("accessToken")
                                
                                if refresh_token:
                                    self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully logged in with form data {self.mask_account(email)}{Style.RESET_ALL}")
                                    return access_token, refresh_token
                        break  # Stop trying variants after form attempt
                    else:
                        self.log(f"{Fore.RED + Style.BRIGHT}Login failed for {self.mask_account(email)}: {response.status_code}{Style.RESET_ALL}")
                        continue  # Try next variant
                    
                    # If we successfully got data, break from variant loop
                    if response.status_code == 200:
                        break
                    
            except Exception as e:
                self.log(f"{Fore.RED + Style.BRIGHT}Error in login attempt {attempt + 1} for {self.mask_account(email)}: {e}{Style.RESET_ALL}")
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    
        return None, None
        
    async def process_account(self, email: str, password: str, use_proxy: bool):
        """Process a single account"""
        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
    
        self.log(
            f"{Fore.CYAN + Style.BRIGHT}Proxy  :{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} {proxy or 'None'} {Style.RESET_ALL}"
        )

        # Add initial random delay
        initial_delay = random.uniform(0.1, 0.8)
        await asyncio.sleep(initial_delay)

        # Login and get tokens
        login_result = await self.auth_login(email, password, proxy)
        if not login_result or len(login_result) != 2:
            return None
        
        access_token, refresh_token = login_result
        if not access_token or not refresh_token:
            return None
        
        # Fetch real user_id and device_id from API endpoints (like manual JS version)
        self.log(f"{Fore.CYAN + Style.BRIGHT}📋 Fetching real user and device information from API...{Style.RESET_ALL}")
        
        # Fetch user_id from /auth/me endpoint
        user_id = await self.fetch_user_info(access_token, proxy)
        if not user_id:
            self.log(f"{Fore.RED + Style.BRIGHT}❌ Failed to fetch user information - falling back to JWT extraction{Style.RESET_ALL}")
            user_id = self.extract_user_id_from_token(refresh_token)
        
        # Fetch device_id from /devices endpoint  
        device_id = await self.fetch_device_info(access_token, proxy)
        if not device_id:
            self.log(f"{Fore.RED + Style.BRIGHT}❌ Failed to fetch device information - using fallback generation{Style.RESET_ALL}")
            device_id = f"{user_id}-device" if user_id else "default_device"
        
        # Validate we have proper values
        if not user_id or user_id == "default_user":
            self.log(f"{Fore.RED + Style.BRIGHT}❌ Invalid user_id: {user_id}{Style.RESET_ALL}")
            return None
            
        if not device_id or device_id == "default_device":
            self.log(f"{Fore.RED + Style.BRIGHT}❌ Invalid device_id: {device_id}{Style.RESET_ALL}")
            return None
        
        # Generate timestamps and payloads using real API data (like working JS version)
        timestamp = int(datetime.now().timestamp() * 1000)
        
        self.log(f"{Fore.GREEN + Style.BRIGHT}🔧 Generating payloads with REAL API data...{Style.RESET_ALL}")
        self.log(f"{Fore.GREEN + Style.BRIGHT}   ✅ User ID: {user_id} (from /auth/me){Style.RESET_ALL}")
        self.log(f"{Fore.GREEN + Style.BRIGHT}   ✅ Device ID: {device_id} (from /devices){Style.RESET_ALL}")
        self.log(f"{Fore.GREEN + Style.BRIGHT}   ✅ Timestamp: {timestamp}{Style.RESET_ALL}")
        
        # HYBRID APPROACH: Use JavaScript generate_payload.js for payload generation
        self.log(f"{Fore.YELLOW + Style.BRIGHT}🧪 TESTING: Using JavaScript generate_payload.js script...{Style.RESET_ALL}")
        
        try:
            # Create a temporary input file for the JS script
            input_data = {
                "user_id": user_id,
                "device_id": device_id,
                "timestamp": timestamp
            }
            
            with open("temp_input.json", "w") as f:
                json.dump(input_data, f)
            
            # Call the JavaScript script
            import subprocess
            import os
            
            # Create a simple JS script that takes our input and generates payloads
            js_script = f"""
const fs = require('fs');

function Ts(e) {{
  let t = 0, i = 1;
  for (let s = 0; s < e; s++) [t, i] = [i, t + i];
  return t % 20;
}}
function Bs(e) {{
  return [...e].map((t, i) => String.fromCharCode(t.charCodeAt(0) + Ts(i))).join("");
}}
function Rs(e) {{
  return [...e].map((t, i) => String.fromCharCode((t.charCodeAt(0) ^ i % 256) & 255)).join("");
}}
function Ss(e) {{
  const t = [...e];
  for (let i = 0; i < t.length - 1; i += 2) [t[i], t[i + 1]] = [t[i + 1], t[i]];
  return t.join("");
}}
function Ur(e) {{
  return btoa(Ss(Rs(Bs(JSON.stringify(e)))));
}}
function register(userId, timestamp) {{
  return {{
    user_id: userId,
    device_info: {{
      "cpu_cores": 1,
      "memory_gb": 0,
      "screen_width_px": 375,
      "screen_height_px": 600,
      "color_depth": 30,
      "scale_factor": 1,
      "browser_name": "chrome",
      "device_type": "extension",
      "language": "id-ID",
      "timezone": "Asia/Jakarta"
    }},
    browser_name: "chrome",
    device_type: "extension",
    timestamp: timestamp
  }}
}}
function uptime(userId, deviceId, timestamp) {{
  return {{
    duration: 600000,
    user_id: userId,
    device_id: deviceId,
    device_type: "telegram",
    timestamp: timestamp
  }}
}}

// Read input
const input = JSON.parse(fs.readFileSync('temp_input.json', 'utf8'));
const registerPayload = Ur(register(input.user_id, input.timestamp));
const uptimePayload = Ur(uptime(input.user_id, input.device_id, input.timestamp));

// Write output
const output = {{
  registerPayload: registerPayload,
  uptimePayload: uptimePayload
}};
fs.writeFileSync('temp_output.json', JSON.stringify(output));
console.log('Payloads generated successfully');
"""
            
            with open("temp_payload_generator.js", "w") as f:
                f.write(js_script)
            
            # Run the JavaScript script
            result = subprocess.run(["node", "temp_payload_generator.js"], 
                                  capture_output=True, text=True, cwd=os.getcwd())
            
            if result.returncode == 0:
                # Read the generated payloads
                with open("temp_output.json", "r") as f:
                    output = json.load(f)
                
                register_payload = output["registerPayload"]
                uptime_payload = output["uptimePayload"]
                
                self.log(f"{Fore.GREEN + Style.BRIGHT}✅ JavaScript payload generation successful!{Style.RESET_ALL}")
                self.log(f"{Fore.BLUE + Style.BRIGHT}Generated payloads:{Style.RESET_ALL}")
                self.log(f"{Fore.BLUE + Style.BRIGHT}   Register: {register_payload[:50]}...{Style.RESET_ALL}")
                self.log(f"{Fore.BLUE + Style.BRIGHT}   Uptime: {uptime_payload[:50]}...{Style.RESET_ALL}")
                
                # Clean up temp files
                try:
                    os.remove("temp_input.json")
                    os.remove("temp_output.json")
                    os.remove("temp_payload_generator.js")
                except:
                    pass
                    
            else:
                self.log(f"{Fore.RED + Style.BRIGHT}❌ JavaScript execution failed: {result.stderr}{Style.RESET_ALL}")
                # Fallback to Python implementation
                register_data = self.create_register_payload(user_id, timestamp)
                uptime_data = self.create_uptime_payload(user_id, device_id, timestamp)
                register_payload = self.generate_payload(register_data)
                uptime_payload = self.generate_payload(uptime_data)
                
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}❌ JavaScript payload generation failed: {e}{Style.RESET_ALL}")
            # Fallback to Python implementation
            register_data = self.create_register_payload(user_id, timestamp)
            uptime_data = self.create_uptime_payload(user_id, device_id, timestamp)
            register_payload = self.generate_payload(register_data)
            uptime_payload = self.generate_payload(uptime_data)
        
        # Save account data
        account_data = {
            "refreshToken": refresh_token,
            "registerPayload": register_payload,
            "uptimePayload": uptime_payload
        }
        
        save_success = self.save_accounts([account_data])
        
        if save_success:
            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Status :{Style.RESET_ALL}"
                f"{Fore.GREEN + Style.BRIGHT} ✅ Account Have Been Saved Successfully (REAL API DATA) {Style.RESET_ALL}"
            )
            return account_data
        else:
            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Status :{Style.RESET_ALL}"
                f"{Fore.RED + Style.BRIGHT} ❌ Failed To Save Account {Style.RESET_ALL}"
            )
            return None

    async def process_single_account(self, account, use_proxy, idx, total_accounts, semaphore):
        """Process a single account with semaphore for rate limiting"""
        async with semaphore:
            email = account["Email"]
            password = account["Password"]
            
            self.log(
                f"{Fore.CYAN + Style.BRIGHT}=========================[{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {idx} {Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT}Of{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {total_accounts} {Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT}]========================={Style.RESET_ALL}"
            )

            if not "@" in email or not password:
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Invalid Account Data {Style.RESET_ALL}"
                )
                return None

            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Account:{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {self.mask_account(email)} {Style.RESET_ALL}"
            )

            # Process account
            result = await self.process_account(email, password, use_proxy)
            
            # Add random delay between accounts
            final_delay = random.uniform(0.1, 0.5)
            await asyncio.sleep(final_delay)
            
            return result

    async def setup_accounts_parallel(self, accounts, use_proxy):
        """Setup accounts in parallel"""
        # Create semaphore to limit concurrent requests
        max_concurrent = min(15, len(accounts))
        semaphore = asyncio.Semaphore(max_concurrent)
        
        self.log(
            f"{Fore.GREEN + Style.BRIGHT}🚀 Processing {len(accounts)} accounts in parallel with {max_concurrent} concurrent workers{Style.RESET_ALL}"
        )
        
        # Create tasks for all accounts
        tasks = []
        for idx, account in enumerate(accounts, start=1):
            if account:
                task = asyncio.create_task(
                    self.process_single_account(account, use_proxy, idx, len(accounts), semaphore)
                )
                tasks.append(task)
                
                # Shorter delay between task creation
                if idx < len(accounts):
                    await asyncio.sleep(random.uniform(0.1, 0.3))
        
        self.log(f"{Fore.BLUE + Style.BRIGHT}Waiting for all {len(tasks)} setup tasks to complete...{Style.RESET_ALL}")
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_count = 0
        failed_count = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.log(f"{Fore.RED + Style.BRIGHT}Task {i+1} failed with exception: {result}{Style.RESET_ALL}")
                failed_count += 1
            elif result:
                successful_count += 1
            else:
                failed_count += 1
        
        self.log(
            f"{Fore.GREEN + Style.BRIGHT}Parallel Setup Results: ✅ {successful_count} successful, ❌ {failed_count} failed{Style.RESET_ALL}"
        )
    
    async def main(self):
        try:
            accounts = self.load_login_accounts()
            if not accounts:
                self.log(f"{Fore.RED + Style.BRIGHT}No Login Accounts Found. Please fill login_accounts.json{Style.RESET_ALL}")
                return
            
            # Load 2captcha key
            captcha_key = self.load_2captcha_key()
            if captcha_key:
                self.CAPTCHA_KEY = captcha_key
                self.log(f"{Fore.GREEN + Style.BRIGHT}🔐 2captcha API key loaded successfully{Style.RESET_ALL}")
            else:
                self.log(f"{Fore.YELLOW + Style.BRIGHT}⚠️ No 2captcha API key found - continuing without captcha support{Style.RESET_ALL}")
                self.log(f"{Fore.CYAN + Style.BRIGHT}💡 Login should work without captcha based on testing{Style.RESET_ALL}")
                # Don't return, continue without captcha

            use_proxy_choice = self.print_question()
            processing_choice = self.print_processing_question()

            use_proxy = False
            if use_proxy_choice in [1, 2]:
                use_proxy = True

            self.clear_terminal()
            self.welcome()
            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Login Account's Total: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
            )

            if use_proxy:
                await self.load_proxies(use_proxy_choice)

            if processing_choice == 1:
                # SEQUENTIAL METHOD 
                separator = "="*25
                for idx, account in enumerate(accounts, start=1):
                    if account:
                        email = account["Email"]
                        password = account["Password"]
                        self.log(
                            f"{Fore.CYAN + Style.BRIGHT}{separator}[{Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT} {idx} {Style.RESET_ALL}"
                            f"{Fore.CYAN + Style.BRIGHT}Of{Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT} {len(accounts)} {Style.RESET_ALL}"
                            f"{Fore.CYAN + Style.BRIGHT}]{separator}{Style.RESET_ALL}"
                        )

                        if not "@" in email or not password:
                            self.log(
                                f"{Fore.CYAN+Style.BRIGHT}Status :{Style.RESET_ALL}"
                                f"{Fore.RED+Style.BRIGHT} Invalid Account Data {Style.RESET_ALL}"
                            )
                            continue

                        self.log(
                            f"{Fore.CYAN + Style.BRIGHT}Account:{Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT} {self.mask_account(email)} {Style.RESET_ALL}"
                        )

                        await self.process_account(email, password, use_proxy)
                        await asyncio.sleep(3)
            else:
                # PARALLEL METHOD
                separator = "="*75
                self.log(f"{Fore.CYAN + Style.BRIGHT}{separator}{Style.RESET_ALL}")
                await self.setup_accounts_parallel(accounts, use_proxy)
                self.log(f"{Fore.CYAN + Style.BRIGHT}{separator}{Style.RESET_ALL}")

            self.log(f"{Fore.CYAN + Style.BRIGHT}{'='*68}{Style.RESET_ALL}")

        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e

    def load_2captcha_key(self):
        try:
            if not os.path.exists("2captcha_key.txt"):
                # Create template file
                with open("2captcha_key.txt", 'w') as file:
                    file.write("your_2captcha_api_key_here")
                self.log(f"{Fore.YELLOW + Style.BRIGHT}Created template 2captcha_key.txt. Please add your 2captcha API key and run again.{Style.RESET_ALL}")
                return None
                
            with open("2captcha_key.txt", 'r') as file:
                captcha_key = file.read().strip()
                
            # Check if it's still the template
            if captcha_key == "your_2captcha_api_key_here" or len(captcha_key) < 10:
                return None
                
            return captcha_key
        except Exception as e:
            return None

    async def solve_cf_turnstile(self, email: str, proxy=None, retries=5):
        """Solve CloudFlare Turnstile captcha using 2captcha"""
        if self.CAPTCHA_KEY is None:
            self.log(f"{Fore.RED + Style.BRIGHT}No 2captcha API key available{Style.RESET_ALL}")
            return False
        
        # First try to find the actual site key from the login page
        site_key = await self.find_turnstile_site_key(proxy)
        if site_key:
            self.log(f"{Fore.GREEN + Style.BRIGHT}Found Turnstile site key: {site_key}{Style.RESET_ALL}")
            site_keys_to_try = [site_key]
        else:
            self.log(f"{Fore.YELLOW + Style.BRIGHT}Could not find site key, trying common patterns{Style.RESET_ALL}")
            site_keys_to_try = self.SITE_KEYS
            
        for site_key in site_keys_to_try:
            self.log(f"{Fore.CYAN + Style.BRIGHT}Trying site key: {site_key}{Style.RESET_ALL}")
            
            for attempt in range(retries):
                try:
                    # Add random delay before each captcha attempt (0.1-0.8 seconds)
                    delay = random.uniform(0.1, 0.8)
                    await asyncio.sleep(delay)
                    
                    self.log(f"{Fore.MAGENTA + Style.BRIGHT}🔐 Solving captcha for {self.mask_account(email)} (attempt {attempt + 1}/{retries}){Style.RESET_ALL}")
                    
                    # Submit captcha to 2captcha
                    url = f"http://2captcha.com/in.php?key={self.CAPTCHA_KEY}&method=turnstile&sitekey={site_key}&pageurl={self.PAGE_URL}"
                    response = await asyncio.to_thread(requests.get, url=url, proxy=proxy, timeout=60, impersonate="chrome110", verify=False)
                    response.raise_for_status()
                    result = response.text

                    if 'OK|' not in result:
                        self.log(f"{Fore.YELLOW + Style.BRIGHT}Failed to submit captcha: {result}{Style.RESET_ALL}")
                        await asyncio.sleep(5)
                        continue

                    request_id = result.split('|')[1]
                    self.log(
                        f"{Fore.MAGENTA + Style.BRIGHT}    >{Style.RESET_ALL}"
                        f"{Fore.BLUE + Style.BRIGHT} Captcha submitted, Req Id: {Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT}{request_id}{Style.RESET_ALL}"
                    )

                    # Poll for result with shorter timeout for testing
                    for poll_attempt in range(20):  # Reduced from 30 to 20
                        poll_delay = random.uniform(3.0, 5.0)  # Reduced from 4-6 to 3-5
                        await asyncio.sleep(poll_delay)
                        
                        res_url = f"http://2captcha.com/res.php?key={self.CAPTCHA_KEY}&action=get&id={request_id}"
                        res_response = await asyncio.to_thread(requests.get, url=res_url, proxy=proxy, timeout=60, impersonate="chrome110", verify=False)
                        res_response.raise_for_status()
                        res_result = res_response.text

                        if 'OK|' in res_result:
                            captcha_token = res_result.split('|')[1]
                            self.captcha_tokens[email] = captcha_token
                            self.log(
                                f"{Fore.MAGENTA + Style.BRIGHT}    >{Style.RESET_ALL}"
                                f"{Fore.BLUE + Style.BRIGHT} Status: {Style.RESET_ALL}"
                                f"{Fore.GREEN + Style.BRIGHT}✅ Captcha solved successfully{Style.RESET_ALL}"
                            )
                            return True
                        elif res_result == "CAPCHA_NOT_READY":
                            if poll_attempt < 10:  # Only show first 10 waiting messages
                                self.log(
                                    f"{Fore.MAGENTA + Style.BRIGHT}    >{Style.RESET_ALL}"
                                    f"{Fore.BLUE + Style.BRIGHT} Status: {Style.RESET_ALL}"
                                    f"{Fore.YELLOW + Style.BRIGHT}⏳ Captcha not ready, waiting... ({poll_attempt + 1}/20){Style.RESET_ALL}"
                                )
                            continue
                        elif "ERROR_CAPTCHA_UNSOLVABLE" in res_result:
                            self.log(
                                f"{Fore.MAGENTA + Style.BRIGHT}    >{Style.RESET_ALL}"
                                f"{Fore.BLUE + Style.BRIGHT} Status: {Style.RESET_ALL}"
                                f"{Fore.RED + Style.BRIGHT}❌ Captcha unsolvable with this site key{Style.RESET_ALL}"
                            )
                            break  # Try next site key
                        else:
                            self.log(
                                f"{Fore.MAGENTA + Style.BRIGHT}    >{Style.RESET_ALL}"
                                f"{Fore.BLUE + Style.BRIGHT} Status: {Style.RESET_ALL}"
                                f"{Fore.RED + Style.BRIGHT}❌ Captcha solving failed: {res_result}{Style.RESET_ALL}"
                            )
                            break

                except Exception as e:
                    self.log(f"{Fore.RED + Style.BRIGHT}Error solving captcha for {self.mask_account(email)} (attempt {attempt + 1}): {e}{Style.RESET_ALL}")
                    if attempt < retries - 1:
                        await asyncio.sleep(5)
                        continue
                
                # If we get here, this site key didn't work, try the next one
                break

        self.log(f"{Fore.RED + Style.BRIGHT}❌ Failed to solve captcha for {self.mask_account(email)} after trying all site keys{Style.RESET_ALL}")
        return False

    async def find_turnstile_site_key(self, proxy=None):
        """Try to find the actual Turnstile site key from the login page"""
        try:
            response = await asyncio.to_thread(
                requests.get,
                url=self.PAGE_URL,
                proxy=proxy,
                timeout=30,
                impersonate="chrome110",
                verify=False
            )
            
            if response.status_code == 200:
                content = response.text
                # Look for common Turnstile patterns
                import re
                
                # Pattern 1: data-sitekey attribute
                sitekey_match = re.search(r'data-sitekey=["\']([^"\']+)["\']', content)
                if sitekey_match:
                    return sitekey_match.group(1)
                
                # Pattern 2: turnstile.render calls
                render_match = re.search(r'turnstile\.render\([^,]+,\s*["\']([^"\']+)["\']', content)
                if render_match:
                    return render_match.group(1)
                
                # Pattern 3: sitekey in script
                script_match = re.search(r'sitekey:\s*["\']([^"\']+)["\']', content)
                if script_match:
                    return script_match.group(1)
                    
        except Exception as e:
            self.log(f"{Fore.YELLOW + Style.BRIGHT}Could not fetch login page to find site key: {e}{Style.RESET_ALL}")
            
        return None

    async def test_login_without_captcha(self, email: str, password: str, proxy=None):
        """Test login without captcha to see if it's always required"""
        self.log(f"{Fore.YELLOW + Style.BRIGHT}Testing if captcha is required...{Style.RESET_ALL}")
        
        # Use the correct signin endpoint
        url = "https://api.optimai.network/auth/signin"
        
        try:
            # Generate PKCE parameters for OAuth 2.0
            code_verifier, code_challenge = self.generate_pkce_challenge()
            
            # Try different data formats and field names with PKCE and turnstile
            json_data_variants = [
                {
                    "email": email,
                    "password": password,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "turnstile_token": ""
                },
                {
                    "email": email,
                    "password": password,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "turnstile_token": "",
                    "remember": False
                },
                {
                    "email": email,
                    "password": password,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "turnstile_token": "",
                    "client_id": "optimai-web",
                    "response_type": "code"
                }
            ]
            
            # Enhanced headers to match browser requests
            headers_json = {
                **self.headers,
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            }
            
            # Try each data variant
            for variant_idx, json_data in enumerate(json_data_variants):
                if variant_idx > 0:
                    self.log(f"{Fore.YELLOW + Style.BRIGHT}Trying data variant {variant_idx + 1}: {list(json_data.keys())}{Style.RESET_ALL}")
                
                response = await asyncio.to_thread(
                    requests.post, 
                    url=url, 
                    headers=headers_json, 
                    json=json_data,
                    proxy=proxy, 
                    timeout=60, 
                    impersonate="chrome110", 
                    verify=False
                )
                
                self.log(f"{Fore.CYAN + Style.BRIGHT}Login response status for {self.mask_account(email)}: {response.status_code}{Style.RESET_ALL}")
                
                # Debug: Print response content for 400 errors
                if response.status_code == 400:
                    try:
                        error_detail = response.json()
                        self.log(f"{Fore.RED + Style.BRIGHT}400 Error details: {error_detail}{Style.RESET_ALL}")
                    except:
                        self.log(f"{Fore.RED + Style.BRIGHT}400 Error response: {response.text[:200]}{Style.RESET_ALL}")
                
                if response.status_code == 200:
                    result = response.json()
                    self.log(f"{Fore.BLUE + Style.BRIGHT}Login success response: {result}{Style.RESET_ALL}")
                    
                    if result.get("success") or "refresh_token" in result or "refreshToken" in result:
                        # Extract refresh token (could be in different keys)
                        refresh_token = result.get("refresh_token") or result.get("refreshToken")
                        access_token = result.get("access_token") or result.get("accessToken")
                        
                        if refresh_token:
                            self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully logged in {self.mask_account(email)}{Style.RESET_ALL}")
                            return access_token, refresh_token
                        else:
                            self.log(f"{Fore.RED + Style.BRIGHT}Missing refresh token in login response for {self.mask_account(email)}{Style.RESET_ALL}")
                            continue
                    elif "code" in result or "authorization_code" in result:
                        # OAuth flow - we got an authorization code, need to exchange it for tokens
                        auth_code = result.get("code") or result.get("authorization_code")
                        self.log(f"{Fore.YELLOW + Style.BRIGHT}Got OAuth code: {auth_code}, exchanging for tokens...{Style.RESET_ALL}")
                        
                        # Exchange code for tokens
                        token_response = await self.exchange_oauth_code(auth_code, code_verifier, proxy)
                        if token_response:
                            access_token, refresh_token = token_response
                            if access_token and refresh_token:
                                self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully logged in via OAuth {self.mask_account(email)}{Style.RESET_ALL}")
                                return access_token, refresh_token
                            else:
                                self.log(f"{Fore.RED + Style.BRIGHT}Missing tokens in OAuth exchange for {self.mask_account(email)}{Style.RESET_ALL}")
                                continue
                    else:
                        self.log(f"{Fore.RED + Style.BRIGHT}Login failed for {self.mask_account(email)}: {result.get('message', result)}{Style.RESET_ALL}")
                        return None, None
                elif response.status_code == 401:
                    self.log(f"{Fore.RED + Style.BRIGHT}Invalid credentials for {self.mask_account(email)}{Style.RESET_ALL}")
                    return None, None
                elif response.status_code == 403:
                    self.log(f"{Fore.RED + Style.BRIGHT}Cloudflare blocked request for {self.mask_account(email)} - trying different approach{Style.RESET_ALL}")
                    continue  # Try next variant
                elif response.status_code == 404:
                    self.log(f"{Fore.RED + Style.BRIGHT}Login endpoint not found for {self.mask_account(email)} - API may have changed{Style.RESET_ALL}")
                    break  # Endpoint is wrong, no point trying variants
                elif response.status_code == 405:
                    self.log(f"{Fore.YELLOW + Style.BRIGHT}Method not allowed - trying form data for {self.mask_account(email)}{Style.RESET_ALL}")
                    
                    # Try with form data if JSON fails with 405
                    headers_form = {
                        **self.headers,
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                    
                    form_data = {
                        "email": email,
                        "password": password
                    }
                    
                    response_form = await asyncio.to_thread(
                        requests.post, 
                        url=url, 
                        headers=headers_form, 
                        data=form_data,
                        proxy=proxy, 
                        timeout=60, 
                        impersonate="chrome110", 
                        verify=False
                    )
                    
                    if response_form.status_code == 200:
                        result = response_form.json()
                        if result.get("success") or "refresh_token" in result or "refreshToken" in result:
                            refresh_token = result.get("refresh_token") or result.get("refreshToken")
                            access_token = result.get("access_token") or result.get("accessToken")
                            
                            if refresh_token:
                                self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully logged in with form data {self.mask_account(email)}{Style.RESET_ALL}")
                                return access_token, refresh_token
                    return None, None
                else:
                    self.log(f"{Fore.RED + Style.BRIGHT}Login failed for {self.mask_account(email)}: {response.status_code}{Style.RESET_ALL}")
                    return None, None
                
                # If we successfully got data, break from variant loop
                if response.status_code == 200:
                    break
                
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Error in login attempt: {e}{Style.RESET_ALL}")
            return None, None

    async def fetch_user_info(self, access_token, proxy=None):
        """Fetch user information from /auth/me endpoint"""
        url = "https://api.optimai.network/auth/me?platforms=all"
        
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": f"Bearer {access_token}",
            "Origin": "https://node.optimai.network",
            "Referer": "https://node.optimai.network/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": self.USER_AGENT
        }
        
        try:
            self.log(f"{Fore.CYAN + Style.BRIGHT}🔍 Fetching user info from /auth/me...{Style.RESET_ALL}")
            response = await asyncio.to_thread(
                requests.get,
                url=url,
                headers=headers,
                proxy=proxy,
                timeout=60,
                impersonate="chrome110",
                verify=False
            )
            
            self.log(f"{Fore.CYAN + Style.BRIGHT}User info response status: {response.status_code}{Style.RESET_ALL}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"{Fore.BLUE + Style.BRIGHT}User info response: {json.dumps(result, indent=2)[:300]}...{Style.RESET_ALL}")
                
                user_id = result.get("user", {}).get("id")
                if user_id:
                    self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully fetched user ID: {user_id}{Style.RESET_ALL}")
                    return user_id
                else:
                    self.log(f"{Fore.RED + Style.BRIGHT}❌ No user.id found in response{Style.RESET_ALL}")
                    return None
            else:
                try:
                    error_detail = response.json()
                    self.log(f"{Fore.RED + Style.BRIGHT}❌ User info fetch failed ({response.status_code}): {error_detail}{Style.RESET_ALL}")
                except:
                    self.log(f"{Fore.RED + Style.BRIGHT}❌ User info fetch failed: {response.status_code} - {response.text[:200]}{Style.RESET_ALL}")
                return None
                
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}❌ Error fetching user info: {e}{Style.RESET_ALL}")
            return None

    async def fetch_device_info(self, access_token, proxy=None):
        """Fetch device information from /devices endpoint"""
        url = "https://api.optimai.network/devices?limit=10&sort_by=last_used_at"
        
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": f"Bearer {access_token}",
            "Origin": "https://node.optimai.network",
            "Referer": "https://node.optimai.network/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": self.USER_AGENT
        }
        
        try:
            self.log(f"{Fore.CYAN + Style.BRIGHT}🔍 Fetching device info from /devices...{Style.RESET_ALL}")
            response = await asyncio.to_thread(
                requests.get,
                url=url,
                headers=headers,
                proxy=proxy,
                timeout=60,
                impersonate="chrome110",
                verify=False
            )
            
            self.log(f"{Fore.CYAN + Style.BRIGHT}Device info response status: {response.status_code}{Style.RESET_ALL}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"{Fore.BLUE + Style.BRIGHT}Device info response: {json.dumps(result, indent=2)[:300]}...{Style.RESET_ALL}")
                
                devices = result.get("items", [])
                if devices and len(devices) > 0:
                    device_id = devices[0].get("id")
                    device_name = devices[0].get("name", "Unknown")
                    if device_id:
                        self.log(f"{Fore.GREEN + Style.BRIGHT}✅ Successfully fetched device ID: {device_id} ({device_name}){Style.RESET_ALL}")
                        return device_id
                    else:
                        self.log(f"{Fore.RED + Style.BRIGHT}❌ No device.id found in first device{Style.RESET_ALL}")
                        return None
                else:
                    self.log(f"{Fore.YELLOW + Style.BRIGHT}⚠️ No devices found in response - user may not have registered devices yet{Style.RESET_ALL}")
                    return None
            else:
                try:
                    error_detail = response.json()
                    self.log(f"{Fore.RED + Style.BRIGHT}❌ Device info fetch failed ({response.status_code}): {error_detail}{Style.RESET_ALL}")
                except:
                    self.log(f"{Fore.RED + Style.BRIGHT}❌ Device info fetch failed: {response.status_code} - {response.text[:200]}{Style.RESET_ALL}")
                return None
                
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}❌ Error fetching device info: {e}{Style.RESET_ALL}")
            return None

if __name__ == "__main__":
    try:
        bot = OptimaiSetup()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(f"""
{Fore.YELLOW + Style.BRIGHT}╔════════════════════════════════════════════════════════════════════╗
║  {Fore.RED + Style.BRIGHT}🛑 SETUP CANCELLED 🛑{Fore.YELLOW + Style.BRIGHT}                                         ║
║                                                                    ║
║  {Fore.WHITE + Style.BRIGHT}👋 Setup interrupted by user{Fore.YELLOW + Style.BRIGHT}                                ║
║  {Fore.WHITE + Style.BRIGHT}💡 Run again when ready to continue{Fore.YELLOW + Style.BRIGHT}                        ║
║                                                                    ║
║  {Fore.CYAN + Style.BRIGHT}📧 Enhanced for OptimAi Network{Fore.YELLOW + Style.BRIGHT}                            ║
╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """)
    except Exception as e:
        print(f"""
{Fore.RED + Style.BRIGHT}╔════════════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW + Style.BRIGHT}💥 SETUP ERROR 💥{Fore.RED + Style.BRIGHT}                                             ║
║                                                                    ║
║  {Fore.WHITE + Style.BRIGHT}❌ Setup failed: {str(e)[:45]}...{Fore.RED + Style.BRIGHT}                               ║
║  {Fore.WHITE + Style.BRIGHT}📞 Please check your configuration{Fore.RED + Style.BRIGHT}                            ║
║                                                                    ║
║  {Fore.CYAN + Style.BRIGHT}📧 Enhanced for OptimAi Network{Fore.RED + Style.BRIGHT}                              ║
╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """)
        raise 