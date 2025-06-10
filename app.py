import csv
import json
import os
import logging
import time
import asyncio
from fastapi import FastAPI, WebSocket, Request, WebSocketDisconnect
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import ldap3
import wmi
import win32com.client
import pythoncom
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Iterator, Tuple
from queue import Queue, Empty
import threading
import re
import subprocess
import win32security
import win32api
import win32con
import pywintypes
import sys


def resource_path(relative_path):
    """Получить путь к ресурсу в .exe или в обычной папке"""
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

app = FastAPI()
templates = Jinja2Templates(directory=resource_path("templates"))
app.mount("/static", StaticFiles(directory=resource_path("static")), name="static")

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class Scanner:
    def __init__(self):
        self.reset()
        self._netbios_to_dns = {}
        self._dns_to_netbios = {}
        self._group_member_cache = {}
        self.local_admin_sid = "S-1-5-32-544"
        self.excluded_accounts = [
            "NT AUTHORITY\\SYSTEM",
            "NT AUTHORITY\\NETWORK SERVICE",
            "NT AUTHORITY\\LOCAL SERVICE"
        ]
        self.recursive = True
        self.no_duplicates = True
        self.show_domain_names = True

    def reset(self):
        self.progress = 0
        self.total = 0
        self.results = []
        self.running = False
        self.active_scan = True
        self.start_time = time.time()
        self.current_computer = ""
        self.admin_groups = ["Administrators", "Администраторы"]
        self.domain_groups_cache = {}
        self.executor = ThreadPoolExecutor(max_workers=15)
        self.ldap_conn = None
        self.result_queue = Queue()

    def _wmi_scan_wrapper(self, computer_name: str) -> Dict[str, Any]:
        if not self.active_scan:
            return {'computer': computer_name, 'error': 'Scan cancelled'}
        if not computer_name or computer_name.strip() == '':
            return {'computer': computer_name, 'error': 'Invalid computer name'}

        pythoncom.CoInitialize()
        try:
            return self.get_local_admins(computer_name)
        except Exception as e:
            logger.error(f"Scan error for {computer_name}: {str(e)}")
            return {'computer': computer_name, 'error': f"General error: {str(e)}"}
        finally:
            pythoncom.CoUninitialize()

    def set_admin_groups(self, groups: List[str]):
        if groups:
            self.admin_groups = [g.strip() for g in groups if g.strip()]
            logger.info(f"Admin groups set: {self.admin_groups}")

    def create_ldap_connection(self, retry_count: int = 3) -> ldap3.Connection:
        server = self.ad_config.get('server')
        port = self.ad_config.get('port', 389)
        domain = self.ad_config.get('domain')
        username = self.ad_config.get('username')
        password = self.ad_config.get('password')
        disable_ssl_verify = self.ad_config.get('disable_ssl_verify', False)
        netbios_domain = self.ad_config.get('netbios_domain', '')

        if '@' in username:
            username = username.split('@')[0]
            logger.debug(f"Normalized username from UPN: {username}")

        user_str = f"{netbios_domain}\\{username}" if netbios_domain else username
        logger.info(f"Attempting LDAP connection with user: {user_str}")

        for attempt in range(retry_count):
            try:
                server_obj = ldap3.Server(
                    f"ldap://{server}:{port}",
                    connect_timeout=60,
                    use_ssl=False if disable_ssl_verify else None
                )

                logger.debug(f"Attempting SIMPLE authentication, attempt {attempt + 1}")
                conn = ldap3.Connection(
                    server=server_obj,
                    user=f"{username}@{domain}",
                    password=password,
                    authentication=ldap3.SIMPLE,
                    auto_bind=True,
                    raise_exceptions=True
                )
                if conn.bind():
                    logger.info("LDAP connection successful via SIMPLE")
                    return conn
            except Exception as e:
                logger.debug(f"SIMPLE connection attempt {attempt + 1} failed: {str(e)}")

            try:
                logger.debug(f"Attempting NTLM authentication, attempt {attempt + 1}")
                conn = ldap3.Connection(
                    server=server_obj,
                    user=user_str,
                    password=password,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                    raise_exceptions=True
                )
                if conn.bind():
                    logger.info("LDAP connection successful via NTLM")
                    return conn
            except Exception as e2:
                logger.warning(f"NTLM connection attempt {attempt + 1} failed: {str(e2)}")
                time.sleep(1)

        logger.error("All LDAP connection attempts failed")
        return None

    def domain_to_dn(self, domain: str) -> str:
        return ",".join(f"dc={part}" for part in domain.split('.'))

    def get_admin_group(self, wmi_conn, computer_name: str, group_name: str) -> Any:
        try:
            name_variants = {
                'administrators': ['Administrators', 'Администраторы'],
                'администраторы': ['Администраторы', 'Administrators']
            }.get(group_name.lower(), [group_name])

            for name in name_variants:
                try:
                    groups = wmi_conn.Win32_Group(Name=name, Domain=computer_name.split('.')[0].upper())
                    if groups:
                        return groups[0]
                except Exception as e:
                    logger.debug(f"Group query {name} error: {str(e)}")
                    continue

            sid_map = {
                "administrators": self.local_admin_sid,
                "администраторы": self.local_admin_sid
            }
            if group_name.lower() in sid_map:
                groups = wmi_conn.Win32_Group(SID=sid_map[group_name.lower()])
                if groups:
                    return groups[0]
            return None
        except Exception as e:
            logger.error(f"Error finding group {group_name}: {str(e)}")
            return None

    def parse_winnt_path(self, path: str, computer: str) -> Tuple[str, str, str]:
        try:
            path = path.replace("WinNT://", "")
            parts = path.split('/')
            domain = ""
            comp = ""
            name = ""

            if len(parts) > 1:
                domain = parts[0]
                if len(parts) > 2:
                    comp = parts[1]
                    name = parts[2]
                else:
                    name = parts[1]
                    if domain.upper() in [computer.upper(), computer.split('.')[0].upper()]:
                        comp = domain
                        domain = ""
            else:
                name = parts[0]

            return domain, comp, name
        except Exception as e:
            logger.error(f"Error parsing WinNT path {path}: {str(e)}")
            return "", "", name

    def get_netbios_from_dns(self, dns_domain: str) -> str:
        if dns_domain.lower() in self._dns_to_netbios:
            return self._dns_to_netbios[dns_domain.lower()]
        try:
            netbios_name = win32api.GetComputerName()
            self._dns_to_netbios[dns_domain.lower()] = netbios_name
            self._netbios_to_dns[netbios_name.lower()] = dns_domain
            return netbios_name
        except Exception as e:
            logger.error(f"Error resolving DNS {dns_domain} to NetBIOS: {str(e)}")
            return dns_domain

    def get_dns_from_netbios(self, netbios_domain: str) -> str:
        if netbios_domain.lower() in self._netbios_to_dns:
            return self._netbios_to_dns[netbios_domain.lower()]
        try:
            dns_name = self.ad_config.get('domain', netbios_domain)
            self._netbios_to_dns[netbios_domain.lower()] = dns_name
            self._dns_to_netbios[dns_name.lower()] = netbios_domain
            return dns_name
        except Exception as e:
            logger.error(f"Error resolving NetBIOS {netbios_domain} to DNS: {str(e)}")
            return netbios_domain

    def get_ad_group_members(self, group_dn: str, computer_name: str, dns_domain: str, nested_list: set) -> List[Dict]:
        logger.debug(f"Fetching AD group members for {group_dn}")
        members = []
        try:
            if not self.ldap_conn:
                logger.debug("No LDAP connection available, skipping AD group members query")
                return members

            self.ldap_conn.search(
                search_base=group_dn,
                search_filter='(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['member', 'sAMAccountName', 'description', 'displayName']
            )
            if not self.ldap_conn.entries:
                logger.error(f"No group found for {group_dn}")
                return members

            entry = self.ldap_conn.entries[0]
            group_sam_account = entry.sAMAccountName.value if 'sAMAccountName' in entry else ""
            group_members = entry.member.values if 'member' in entry else []
            netbios_domain = self.get_netbios_from_dns(dns_domain)

            for member_dn in group_members:
                try:
                    self.ldap_conn.search(
                        search_base=member_dn,
                        search_filter='(objectClass=*)',
                        search_scope=ldap3.BASE,
                        attributes=['sAMAccountName', 'objectSid', 'objectClass', 'description', 'displayName']
                    )
                    if not self.ldap_conn.entries:
                        logger.debug(f"No entry found for {member_dn}")
                        continue

                    member_entry = self.ldap_conn.entries[0]
                    is_fsp = 'foreignSecurityPrincipal' in member_entry.objectClass.values

                    if is_fsp and 'objectSid' in member_entry:
                        try:
                            sid = self._convert_ldap_sid(member_entry.objectSid.raw_values[0])
                            name, domain, _ = win32security.LookupAccountSid(None, member_entry.objectSid.raw_values[0])
                            member_dns_domain = self.get_dns_from_netbios(domain)
                            self.ldap_conn.search(
                                search_base=self.domain_to_dn(member_dns_domain),
                                search_filter=f'(objectSid={sid})',
                                search_scope=ldap3.SUBTREE,
                                attributes=['distinguishedName', 'sAMAccountName', 'objectClass', 'description', 'displayName']
                            )
                            if self.ldap_conn.entries:
                                member_entry = self.ldap_conn.entries[0]
                                is_fsp = 'foreignSecurityPrincipal' in member_entry.objectClass.values
                        except Exception as e:
                            logger.error(f"Error resolving FSP {member_dn}: {str(e)}")
                            continue

                    if 'sAMAccountName' not in member_entry or not member_entry.sAMAccountName.value:
                        logger.debug(f"No sAMAccountName for {member_dn}")
                        continue

                    member_sam_account = member_entry.sAMAccountName.value
                    member_type = 'group' if 'group' in member_entry.objectClass.values else 'user'
                    domain_and_username = f"{netbios_domain}\\{member_sam_account}"

                    if domain_and_username in self.excluded_accounts:
                        logger.debug(f"Skipping excluded account: {domain_and_username}")
                        continue

                    sid = ""
                    if 'objectSid' in member_entry:
                        try:
                            sid = self._convert_ldap_sid(member_entry.objectSid.raw_values[0])
                            logger.debug(f"Converted SID for {domain_and_username}: {sid}")
                        except Exception as e:
                            logger.debug(f"Failed to convert SID for {domain_and_username}: {str(e)}")

                    member_data = {
                        'name': f"{netbios_domain}\\{member_sam_account}" if self.show_domain_names else member_sam_account,
                        'domain_and_username': domain_and_username,
                        'type': member_type,
                        'computer': computer_name,
                        'from_group': f"{netbios_domain}\\{group_sam_account}" if self.show_domain_names else group_sam_account,
                        'description': member_entry.description.value if 'description' in member_entry else "",
                        'display_name': member_entry.displayName.value if 'displayName' in member_entry else "",
                        'sid': sid,
                        'path': member_entry.entry_dn,
                        'is_domain': netbios_domain.upper() != computer_name.split('.')[0].upper()
                    }

                    if self.no_duplicates and any(m['domain_and_username'] == domain_and_username for m in members):
                        logger.debug(f"Skipping duplicate member: {domain_and_username}")
                        continue

                    members.append(member_data)
                    logger.debug(f"Added AD member: {domain_and_username}")
                    if self.recursive and member_type.lower() == 'group' and domain_and_username not in nested_list:
                        nested_list.add(domain_and_username)
                        members.extend(self.get_ad_group_members(member_entry.entry_dn, computer_name, dns_domain, nested_list))

                except Exception as e:
                    logger.error(f"Error processing member {member_dn}: {str(e)}")
                    continue

            self._group_member_cache[group_dn] = members
            logger.debug(f"Cached {len(members)} members for {group_dn}")
            return members

        except Exception as e:
            logger.error(f"Error fetching AD group members for {group_dn}: {str(e)}")
            return members

    def _convert_ldap_sid(self, raw_sid: bytes) -> str:
        try:
            if not isinstance(raw_sid, bytes):
                raise ValueError("SID is not in binary format")
            sid = win32security.ConvertStringSidToSid(win32security.ConvertSidToStringSid(raw_sid))
            return win32security.ConvertSidToStringSid(sid)
        except Exception as e:
            logger.debug(f"Failed to convert LDAP SID: {str(e)}")
            return ""

    def get_local_admins(self, computer_name: str) -> Dict[str, Any]:
        result = {'computer': computer_name, 'groups': {}, 'members': []}
        short_name = computer_name.split('.')[0].upper()
        nested_list = set()

        for attempt in range(2):
            try:
                pythoncom.CoInitialize()
                wmi_username = self.ad_config['username']
                wmi_password = self.ad_config['password']
                wmi_domain = self.ad_config.get('netbios_domain', '')
                user_str = f"{wmi_domain}\\{wmi_username.split('@')[0]}" if wmi_domain else wmi_username.split('@')[0]
                authority = f"kerberos:{self.ad_config['domain']}" if self.ad_config.get('domain') else ""
                logger.info(f"Connecting to {computer_name} as {user_str} with authority {authority}")

                try:
                    logger.debug(f"Attempting WMI connection via pywin32 COM")
                    locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
                    service = locator.ConnectServer(
                        computer_name,
                        "root\\cimv2",
                        user_str,
                        wmi_password,
                        "",  # Locale
                        None,  # Authority (unsupported in pywin32)
                        128,  # SecurityFlags
                        None  # NamedValueSet
                    )
                    service.Security_.ImpersonationLevel = 3
                    service.Security_.AuthenticationLevel = 6
                    service.Security_.Privileges.AddAsString("SeSecurityPrivilege", True)
                    service.Security_.Privileges.AddAsString("SeDebugPrivilege", True)
                    service.Security_.Privileges.AddAsString("SeTcbPrivilege", True)
                    logger.debug(f"COM WMI connection established for {computer_name}")
                    wmi_conn = None
                except pywintypes.com_error as e:
                    logger.debug(f"pywin32 COM connection failed: {str(e)}")
                    logger.debug(f"Falling back to wmi library")
                    for auth_level in ["pktPrivacy", "pktIntegrity", "default"]:
                        try:
                            logger.debug(f"Attempting WMI connection with auth level {auth_level}")
                            wmi_conn = wmi.WMI(
                                computer=computer_name,
                                user=user_str,
                                password=wmi_password,
                                namespace="root\\cimv2",
                                authentication_level=auth_level,
                                impersonation_level="impersonate",
                                authority=authority
                            )
                            service = None
                            logger.debug(f"WMI library connection established for {computer_name}")
                            break
                        except wmi.x_wmi as e2:
                            logger.debug(f"WMI connection failed with {auth_level}: {str(e2)}")
                            if auth_level == "default":
                                raise e2

                try:
                    if service:
                        service.ExecQuery("SELECT * FROM Win32_ComputerSystem")
                    else:
                        wmi_conn.Win32_ComputerSystem()
                    logger.debug(f"WMI access verified for {computer_name}")
                except Exception as e:
                    logger.error(f"WMI access test failed for {computer_name}: {str(e)}")
                    raise e

                for group_name in self.admin_groups:
                    if service:
                        groups = service.ExecQuery(
                            f"SELECT * FROM Win32_Group WHERE Name='{group_name}' AND Domain='{short_name}'"
                        )
                        group_object = groups[0] if groups.count > 0 else None
                    else:
                        group_object = self.get_admin_group(wmi_conn, computer_name, group_name)

                    if not group_object:
                        logger.debug(f"Group {group_name} not found on {computer_name}")
                        continue

                    group_data = {
                        'name': group_name,
                        'sid': group_object.SID if hasattr(group_object, 'SID') else ""
                    }

                    logger.info(f"Processing group: {group_name} on {computer_name}")
                    wql_query = (
                        f"SELECT * FROM Win32_GroupUser WHERE "
                        f"GroupComponent = \"Win32_Group.Name='{group_name}',Domain='{short_name}'\""
                    )
                    try:
                        if service:
                            associations = service.ExecQuery(wql_query)
                        else:
                            associations = wmi_conn.query(wql_query)
                    except Exception as e:
                        logger.error(f"WQL query failed for group {group_name} on {computer_name}: {str(e)}")
                        continue

                    for assoc in associations:
                        if not self.active_scan:
                            return {'computer': computer_name, 'error': 'Scan cancelled'}

                        part_component = assoc.PartComponent
                        if not part_component:
                            continue

                        try:
                            match = re.match(r'Win32_(UserAccount|Group)\.Domain="([^"]+)",Name="([^"]+)"', str(part_component))
                            if not match:
                                logger.debug(f"Invalid PartComponent format: {part_component}")
                                continue

                            obj_type, account_domain, account_name = match.groups()
                            account_type = "user" if obj_type == "UserAccount" else "group"
                            is_domain = account_domain.upper() != short_name and account_domain != "BUILTIN"
                            domain, comp, name = self.parse_winnt_path(f"WinNT://{account_domain}/{account_name}", computer_name)

                            sid = ""
                            try:
                                if service:
                                    account_objs = service.ExecQuery(
                                        f"SELECT SID FROM Win32_Account WHERE Name='{account_name}' AND Domain='{account_domain}'"
                                    )
                                    sid = account_objs[0].SID if account_objs.count > 0 else ""
                                else:
                                    account_obj = wmi_conn.Win32_Account(Name=account_name, Domain=account_domain)
                                    if account_obj:
                                        sid = account_obj[0].SID
                            except Exception as e:
                                logger.debug(f"Failed to get SID for {account_domain}\\{account_name}: {str(e)}")

                            domain_and_username = f"{account_domain}\\{name}"
                            member_data = {
                                'type': account_type,
                                'domain': account_domain,
                                'name': name if self.show_domain_names else account_name,
                                'sid': sid,
                                'is_domain': is_domain,
                                'description': '',
                                'display_name': '',
                                'from_group': group_name,
                                'path': f"WinNT://{account_domain}/{account_name}",
                                'domain_and_username': domain_and_username
                            }

                            if self.show_domain_names and account_domain:
                                member_data['name'] = f"{account_domain}\\{name}"
                                member_data['from_group'] = f"{short_name}\\{group_name}"

                            if domain_and_username in self.excluded_accounts:
                                continue

                            if self.no_duplicates and any(m['domain_and_username'] == domain_and_username for m in result['members']):
                                continue

                            if is_domain and account_type.lower() == 'group':
                                dns_domain = self.get_dns_from_netbios(account_domain)
                                self.ldap_conn.search(
                                    search_base=self.domain_to_dn(dns_domain),
                                    search_filter=f'(sAMAccountName={name})',
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['distinguishedName']
                                )
                                if self.ldap_conn.entries:
                                    nested_list.add(domain_and_username)
                                    result['members'].extend(
                                        self.get_ad_group_members(
                                            self.ldap_conn.entries[0].entry_dn,
                                            computer_name,
                                            dns_domain,
                                            nested_list
                                        )
                                    )
                                else:
                                    result['members'].append(member_data)
                            else:
                                result['members'].append(member_data)

                        except Exception as e:
                            logger.error(f"Error processing member {part_component} for group {group_name}: {str(e)}")
                            continue

                    logger.info(f"Found {len(result['members'])} members in group {group_name}")
                    result['groups'][group_data['name']] = group_data

                if result['groups'] or result['members']:
                    return result
                return {'computer': computer_name, 'error': 'No admin groups or members found'}

            except (pywintypes.com_error, wmi.x_wmi) as e:
                logger.error(f"WMI error for {computer_name}: {str(e)}")
                if attempt == 0:
                    logger.info(f"Retrying WMI connection for {computer_name}...")
                    time.sleep(2)
                else:
                    logger.debug(f"Falling back to PowerShell net localgroup for {computer_name}")
                    try:
                        ps_result = self.get_local_admins_powershell(computer_name)
                        logger.debug(f"PowerShell fallback result for {computer_name}: {ps_result}")
                        return ps_result
                    except Exception as e2:
                        logger.error(f"PowerShell fallback failed for {computer_name}: {str(e2)}")
                        return {'computer': computer_name, 'error': f"WMI and PowerShell failed: {str(e)}"}
            except Exception as e:
                logger.error(f"General connection error for {computer_name}: {str(e)}")
                return {'computer': computer_name, 'error': f"Connection error: {str(e)}"}
            finally:
                pythoncom.CoUninitialize()

        return {'computer': computer_name, 'error': 'Connection attempts failed'}

    def get_local_admins_powershell(self, computer_name: str) -> Dict[str, Any]:
        result = {'computer': computer_name, 'groups': {}, 'members': []}
        short_name = computer_name.split('.')[0].upper()
        wmi_domain = self.ad_config.get('netbios_domain', '')
        user_str = f"{wmi_domain}\\{self.ad_config['username'].split('@')[0]}" if wmi_domain else self.ad_config['username'].split('@')[0]
        password = self.ad_config['password']
        nested_list = set()

        admin_group_name = None
        ps_get_group_name = (
            f"$cred = New-Object System.Management.Automation.PSCredential('{user_str}', "
            f"(ConvertTo-SecureString '{password}' -AsPlainText -Force)); "
            f"$session = New-PSSession -ComputerName '{computer_name}' -Credential $cred -ErrorAction Stop; "
            f"Invoke-Command -Session $session -ScriptBlock {{ "
            f"(Get-LocalGroup -SID 'S-1-5-32-544').Name }}; "
            f"Remove-PSSession $session"
        )
        try:
            logger.debug(f"Fetching Administrators group name for {computer_name}")
            output = subprocess.run(
                ["powershell", "-Command", ps_get_group_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            if output.stdout.strip():
                admin_group_name = output.stdout.strip()
                logger.info(f"Administrators group name for {computer_name}: {admin_group_name}")
            if output.stderr:
                logger.warning(f"Error fetching group name for {computer_name}: {output.stderr}")
        except Exception as e:
            logger.error(f"Failed to fetch Administrators group name for {computer_name}: {str(e)}")

        group_names = [admin_group_name] if admin_group_name else self.admin_groups
        group_names = list(set(group_names))

        for group_name in group_names:
            ps_command = (
                f"$cred = New-Object System.Management.Automation.PSCredential('{user_str}', "
                f"(ConvertTo-SecureString '{password}' -AsPlainText -Force)); "
                f"$session = New-PSSession -ComputerName '{computer_name}' -Credential $cred -ErrorAction Stop; "
                f"Invoke-Command -Session $session -ScriptBlock {{ net localgroup '{group_name}' }}; "
                f"Remove-PSSession $session"
            )
            try:
                logger.debug(f"Executing PowerShell command for {computer_name}, group {group_name}")
                output = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if output.stderr:
                    logger.error(f"PowerShell error for {computer_name}, group {group_name}: {output.stderr}")
                    continue

                group_data = {'name': group_name, 'sid': self.local_admin_sid}
                lines = output.stdout.splitlines()
                logger.debug(f"Raw net localgroup output for {computer_name}, group {group_name}: {lines}")

                if not lines:
                    logger.debug(f"No output for group {group_name} on {computer_name}")
                    result['groups'][group_name] = group_data
                    continue

                members_started = False
                for line in lines:
                    line = line.strip()
                    logger.debug(f"Processing line: {line}")
                    if not line:
                        continue
                    if '---' in line:
                        members_started = True
                        logger.debug("Members section started")
                        continue
                    if members_started and 'The command completed successfully' not in line:
                        try:
                            account_name = line
                            account_domain = short_name
                            if '\\' in line:
                                account_domain, account_name = line.split('\\', 1)
                            logger.debug(f"Parsed member: domain={account_domain}, name={account_name}")

                            if not account_name or account_name.isspace():
                                logger.debug(f"Skipping invalid member name: {line}")
                                continue

                            account_type = 'user'
                            sid = ""
                            is_domain = account_domain.upper() != short_name and account_domain != "BUILTIN"
                            domain, comp, name = self.parse_winnt_path(f"WinNT://{account_domain}/{account_name}", computer_name)
                            domain_and_username = f"{account_domain}\\{name}"

                            if domain_and_username in self.excluded_accounts:
                                logger.debug(f"Skipping excluded account: {domain_and_username}")
                                continue

                            if is_domain and self.ldap_conn:
                                dns_domain = self.get_dns_from_netbios(account_domain)
                                self.ldap_conn.search(
                                    search_base=self.domain_to_dn(dns_domain),
                                    search_filter=f'(sAMAccountName={name})',
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['objectClass', 'objectSid']
                                )
                                if self.ldap_conn.entries:
                                    entry = self.ldap_conn.entries[0]
                                    if 'group' in entry.objectClass.values:
                                        account_type = 'group'
                                        logger.debug(f"Identified {domain_and_username} as group via LDAP")
                                    if 'objectSid' in entry:
                                        try:
                                            sid = self._convert_ldap_sid(entry.objectSid.raw_values[0])
                                            logger.debug(f"LDAP SID for {domain_and_username}: {sid}")
                                        except Exception as e:
                                            logger.debug(f"Failed to convert LDAP SID for {domain_and_username}: {str(e)}")

                            if not sid:
                                try:
                                    ps_sid_command = (
                                        f"$cred = New-Object System.Management.Automation.PSCredential('{user_str}', "
                                        f"(ConvertTo-SecureString '{password}' -AsPlainText -Force)); "
                                        f"$session = New-PSSession -ComputerName '{computer_name}' -Credential $cred -ErrorAction Stop; "
                                        f"Invoke-Command -Session $session -ScriptBlock {{ "
                                        f"try {{ (New-Object System.Security.Principal.NTAccount('{account_domain}', '{account_name}')).Translate([System.Security.Principal.SecurityIdentifier]).Value }} "
                                        f"catch {{ $null }} }}; "
                                        f"Remove-PSSession $session"
                                    )
                                    sid_output = subprocess.run(
                                        ["powershell", "-Command", ps_sid_command],
                                        capture_output=True,
                                        text=True,
                                        timeout=30
                                    )
                                    if sid_output.stdout.strip():
                                        sid = sid_output.stdout.strip()
                                        logger.debug(f"PowerShell SID for {domain_and_username}: {sid}")
                                    if sid_output.stderr:
                                        logger.debug(f"SID lookup error for {domain_and_username}: {sid_output.stderr}")
                                except Exception as e:
                                    logger.debug(f"Failed to get SID via PowerShell for {domain_and_username}: {str(e)}")

                            member_data = {
                                'type': account_type,
                                'domain': account_domain,
                                'name': name if self.show_domain_names else account_name,
                                'sid': sid,
                                'is_domain': is_domain,
                                'description': '',
                                'display_name': '',
                                'from_group': group_name,
                                'path': f"WinNT://{account_domain}/{account_name}",
                                'domain_and_username': domain_and_username
                            }

                            if self.show_domain_names and account_domain:
                                member_data['name'] = f"{account_domain}\\{name}"
                                member_data['from_group'] = f"{short_name}\\{group_name}"

                            if self.no_duplicates and any(m['domain_and_username'] == domain_and_username for m in result['members']):
                                logger.debug(f"Skipping duplicate member: {domain_and_username}")
                                continue

                            result['members'].append(member_data)
                            logger.debug(f"Added member: {domain_and_username}")

                            if is_domain and account_type.lower() == 'group':
                                dns_domain = self.get_dns_from_netbios(account_domain)
                                self.ldap_conn.search(
                                    search_base=self.domain_to_dn(dns_domain),
                                    search_filter=f'(sAMAccountName={name})',
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['distinguishedName']
                                )
                                if self.ldap_conn.entries:
                                    nested_list.add(domain_and_username)
                                    result['members'].extend(
                                        self.get_ad_group_members(
                                            self.ldap_conn.entries[0].entry_dn,
                                            computer_name,
                                            dns_domain,
                                            nested_list
                                        )
                                    )

                        except Exception as e:
                            logger.error(f"Error processing member line '{line}' for group {group_name} on {computer_name}: {str(e)}")
                            continue

                logger.info(f"Found {len(result['members'])} members in group {group_name} via PowerShell net localgroup")
                result['groups'][group_data['name']] = group_data

            except Exception as e:
                logger.error(f"PowerShell query failed for {computer_name}, group {group_name}: {str(e)}")
                continue

        if result['groups'] or result['members']:
            return result
        return {'computer': computer_name, 'error': f"No admin groups or members found via PowerShell for {computer_name}"}

    def get_computers_from_ldap(self, ou: str) -> List[str]:
        if not self.ldap_conn:
            self.ldap_conn = self.create_ldap_connection()
        if not self.ldap_conn:
            logger.error("Failed to establish LDAP connection")
            return []

        base_dn = self.clean_ou_path(ou)
        logger.info(f"Searching computers in: {base_dn}")

        primary_filter = '(&(objectClass=computer)(!(objectCategory=msDS-ManagedServiceAccount)))'
        fallback_filter = '(objectClass=computer)'

        try:
            logger.debug(f"Attempting LDAP search with primary filter: {primary_filter}")
            self.ldap_conn.search(
                search_base=base_dn,
                search_filter=primary_filter,
                search_scope=ldap3.SUBTREE,
                attributes=['dNSHostName', 'name', 'cn'],
                paged_size=500,
                size_limit=0
            )

            computers = []
            for entry in self.ldap_conn.entries:
                if 'dNSHostName' in entry and entry.dNSHostName:
                    comp_name = entry.dNSHostName.value.rstrip('.').split('.')[0]
                    computers.append(comp_name.lower())
                elif 'name' in entry and entry.name:
                    computers.append(entry.name.value.lower())
                elif 'cn' in entry and entry.cn:
                    computers.append(entry.cn.value.lower())

            logger.info(f"Found {len(computers)} computers with primary filter")
            if not computers:
                logger.warning(f"No computers found with primary filter in {base_dn}. Check OU path or filter.")

            return sorted(set(computers))

        except Exception as e:
            logger.error(f"LDAP search error with primary filter: {str(e)}")

            try:
                logger.debug(f"Retrying LDAP search with fallback filter: {fallback_filter}")
                self.ldap_conn.search(
                    search_base=base_dn,
                    search_filter=fallback_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=['dNSHostName', 'name', 'cn'],
                    paged_size=500,
                    size_limit=0
                )

                computers = []
                for entry in self.ldap_conn.entries:
                    if 'dNSHostName' in entry and entry.dNSHostName:
                        comp_name = entry.dNSHostName.value.rstrip('.').split('.')[0]
                        computers.append(comp_name.lower())
                    elif 'name' in entry and entry.name:
                        computers.append(entry.name.value.lower())
                    elif 'cn' in entry and entry.cn:
                        computers.append(entry.cn.value.lower())

                logger.info(f"Found {len(computers)} computers with fallback filter")
                if not computers:
                    logger.warning(f"No computers found with fallback filter in {base_dn}. Check OU path or filter.")

                return sorted(set(computers))

            except Exception as e2:
                logger.error(f"LDAP search error with fallback filter: {str(e2)}")
                return []

    def clean_ou_path(self, ou_path: str) -> str:
        try:
            if "OU=" in ou_path or "DC=" in ou_path:
                return ou_path

            domain_dn = self.domain_to_dn(self.ad_config['domain'])
            if not ou_path:
                return domain_dn

            parts = [part.strip() for part in ou_path.split('/') if part.strip()]
            if not parts:
                return domain_dn

            return ",".join(f"OU={part}" for part in reversed(parts)) + "," + domain_dn
        except Exception as e:
            logger.error(f"Error cleaning OU path {ou_path}: {str(e)}")
            return self.domain_to_dn(self.ad_config['domain'])

    def run_scan(self, config: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        self.reset()
        self.running = True
        self.active_scan = True
        self.show_domain_names = config.get('show_domain_names', True)
        self.ad_config = config.get('ad_config', {})
        self.recursive = config.get('recursive', True)
        self.no_duplicates = config.get('no_duplicates', True)

        try:
            required_params = ['server', 'username', 'password', 'domain']
            missing_params = [param for param in required_params if param not in self.ad_config or not self.ad_config[param]]
            if missing_params:
                error_msg = f"Missing or empty required parameters: {', '.join(missing_params)}"
                logger.error(error_msg)
                yield {'type': 'error', 'message': error_msg}
                return

            if 'admin_groups' in config and config['admin_groups']:
                self.set_admin_groups(config['admin_groups'])

            computers = []
            for ou_type in ['workstations_ou', 'servers_ou']:
                if ou_value := config.get(ou_type):
                    comps = self.get_computers_from_ldap(ou_value)
                    computers.extend(comps)
                    yield {
                        'type': 'info',
                        'message': f"Found {len(comps)} computers in {ou_type}"
                    }

            computers = sorted(set(computers))
            if not computers:
                error_msg = "No computers found in specified OUs"
                logger.error(error_msg)
                yield {'type': 'error', 'message': error_msg}
                return

            self.total = total = len(computers)
            yield {'type': 'info', 'message': f"Total computers to scan: {total}"}

            futures = {self.executor.submit(self._wmi_scan_wrapper, comp): comp for comp in computers}
            completed = 0

            for future in as_completed(futures):
                if not self.active_scan:
                    yield {'type': 'info', 'message': 'Scan stopped by user'}
                    break

                comp = futures[future]
                try:
                    result = future.result(timeout=300)
                    self.results.append(result)
                    status = "Success"

                    if 'groups' in result or 'members' in result:
                        member_count = len(result.get('members', []))
                        group_count = len(result.get('groups', {}))
                        status = f"Found {group_count} group(s) with {member_count} members"

                    completed += 1
                    self.progress = completed

                    yield {
                        'type': 'progress',
                        'progress': completed,
                        'total': total,
                        'percent': int(completed / total * 100),
                        'current': comp,
                        'status': status
                    }

                except Exception as e:
                    completed += 1
                    error_result = {'computer': comp, 'error': str(e)}
                    self.results.append(error_result)
                    logger.error(f"Processing error for {comp}: {str(e)}")
                    yield {
                        'type': 'progress',
                        'progress': completed,
                        'total': total,
                        'percent': int(completed / total * 100),
                        'current': comp,
                        'status': f"Error: {str(e)}"
                    }

            if self.results:
                save_path = config.get('save_path', 'results')
                os.makedirs(save_path, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

                json_path = f"{save_path}/local_admins_{timestamp}.json"
                try:
                    with open(json_path, 'w', encoding='utf-8') as f:
                        json.dump(self.results, f, indent=2, ensure_ascii=False, sort_keys=True)
                    logger.info(f"JSON results saved to {json_path}")
                except Exception as e:
                    error_msg = f"Failed to save JSON results to {json_path}: {str(e)}"
                    logger.error(error_msg)
                    yield {'type': 'error', 'message': error_msg}
                    return

                csv_path = f"{save_path}/local_admins_{timestamp}.csv"
                try:
                    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
                        writer = csv.writer(f, delimiter=';')
                        writer.writerow(['Computer', 'Group', 'Account', 'Domain', 'Type', 'SID', 'Description', 'DisplayName'])

                        for res in self.results:
                            if 'error' in res:
                                writer.writerow([res['computer'], '', '', '', '', '', res['error'], ''])
                                logger.debug(f"Writing error for {res['computer']}: {res['error']}")
                                continue

                            for member in res.get('members', []):
                                try:
                                    writer.writerow([
                                        res['computer'],
                                        member.get('from_group', ''),
                                        member.get('name', ''),
                                        member.get('domain', ''),
                                        member.get('type', ''),
                                        member.get('sid', ''),
                                        member.get('description', ''),
                                        member.get('display_name', '')
                                    ])
                                except Exception as e:
                                    logger.error(f"Error writing CSV row for member {member.get('name', 'unknown')} on {res['computer']}: {str(e)}")
                                    continue

                    logger.info(f"CSV results saved to {csv_path}")
                except Exception as e:
                    error_msg = f"Failed to save CSV results to {csv_path}: {str(e)}"
                    logger.error(error_msg)
                    yield {'type': 'error', 'message': error_msg}
                    return

                runtime = int(time.time() - self.start_time)
                yield {
                    'type': 'completed',
                    'message': f"Scan completed in {runtime} seconds",
                    'json_path': json_path,
                    'csv_path': csv_path,
                    'total': total,
                    'results': self.results
                }

        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            logger.error(error_msg)
            yield {'type': 'error', 'message': error_msg}
        finally:
            self.running = False
            self.active_scan = False
            self.executor.shutdown(wait=False)
            if self.ldap_conn:
                try:
                    self.ldap_conn.unbind()
                except Exception as e:
                    logger.debug(f"Error unbinding LDAP connection: {str(e)}")
                self.ldap_conn = None

    def run_scan_in_thread(self, config: Dict[str, Any], queue: Queue):
        try:
            for progress in self.run_scan(config):
                queue.put(progress)
            queue.put(None)
        except Exception as e:
            logger.error(f"Scan thread error: {str(e)}")
            queue.put({'type': 'error', 'message': f"Scan execution error: {str(e)}"})
            queue.put(None)

scanner = Scanner()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    try:
        await websocket.accept()
        scan_thread = None
        result_queue = Queue()

        async def handle_scan_results():
            nonlocal scan_thread
            try:
                while scanner.running:
                    try:
                        item = result_queue.get(timeout=1.0)
                        if item is None:
                            break
                        if 'sc' in item:
                            scanner.current_computer = item['sc']
                        await websocket.send_json(item)
                    except Empty:
                        continue
                    except WebSocketDisconnect:
                        logger.warning("WebSocket disconnected during scan")
                        break
                    except Exception as e:
                        logger.error(f"WebSocket send error: {str(e)}")
            finally:
                scanner.active_scan = False
                if scan_thread and scan_thread.is_alive():
                    scan_thread.join(timeout=10)
                try:
                    await websocket.close()
                except Exception as e:
                    logger.debug(f"Error closing WebSocket: {str(e)}")

        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                msg = json.loads(data)

                if 'command' in msg:
                    if msg['command'] == 'ping':
                        await websocket.send_json({'type': 'pong'})
                    elif msg['command'] == 'status':
                        await websocket.send_json({
                            'type': 'status',
                            'running': scanner.running,
                            'progress': scanner.progress,
                            'total': scanner.total,
                            'current': scanner.current_computer
                        })
                    elif msg['command'] == 'stop_scan':
                        scanner.active_scan = False
                        await websocket.send_json({'type': 'info', 'message': 'Scan stopped'})
                    continue

                if 'scan' in msg:
                    if scanner.running:
                        await websocket.send_json({
                            'type': 'warning',
                            'message': 'Scan already in progress'
                        })
                        continue

                    scan_thread = threading.Thread(
                        target=scanner.run_scan_in_thread,
                        args=(msg['scan'], result_queue),
                        daemon=True
                    )
                    scan_thread.start()
                    await handle_scan_results()

            except asyncio.TimeoutError:
                logger.debug("WebSocket receive timeout, continuing to listen")
                continue
            except WebSocketDisconnect:
                logger.info("Client disconnected")
                break
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON received: {str(e)}")
                await websocket.send_json({'type': 'error', 'message': 'Invalid message format'})
            except Exception as e:
                logger.error(f"WebSocket error: {str(e)}")
                break

    except Exception as e:
        logger.error(f"WebSocket endpoint error: {str(e)}")
    finally:
        scanner.active_scan = False
        scanner.current_computer = ""
        try:
            await websocket.close()
        except Exception:
            logger.debug(f"Error closing WebSocket in finally: {str(e)}")

@app.get("/download")
async def download_file(path: str):
    if not os.path.exists(path):
        logger.error(f"File not found: {path}")
        return {"error": "File not found"}, 404
    return FileResponse(
        path,
        filename=os.path.basename(path),
        media_type='application/octet-stream'
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")