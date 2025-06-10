Scanner Script Instructions

Overview

The scanner.py script is a Python-based tool for scanning Windows computers in an Active Directory (AD) environment to identify local administrators. It uses WMI, LDAP, and PowerShell to collect data, supports recursive group member enumeration, and outputs results in JSON and CSV formats. The script is built with FastAPI, providing a web interface and WebSocket support for real-time scan progress updates.

Features





Local Admin Discovery: Identifies members of local administrator groups (e.g., "Administrators", "Администраторы") on target computers.



Recursive Group Enumeration: Resolves nested AD group memberships.



Output Formats: Saves results in JSON and CSV files with proper encoding for non-ASCII characters.



Web Interface: Provides a web-based UI for initiating scans and viewing progress.



Real-Time Updates: Uses WebSockets to stream scan progress to the client.



Error Handling: Robust validation and logging to diagnose issues like missing configuration parameters.

Prerequisites





Operating System: Windows (required for WMI and PowerShell functionality).



Python: Version 3.8 or higher.



Network Access: Access to the LDAP server and target computers.



Permissions: Credentials with sufficient privileges to query AD and access WMI on target machines.



Dependencies:

pip install fastapi uvicorn ldap3 wmi pywin32



Directory Structure:





Create a templates folder with index.html (for the web UI).



Create a static folder for CSS/JavaScript files (if used by index.html).

Setup





Install Python:





Download and install Python from python.org.



Ensure pip is available by running pip --version.



Install Dependencies:





Open a terminal and run:

pip install fastapi uvicorn ldap3 wmi pywin32



Create Directory Structure:





Create a project folder (e.g., ad_scanner).



Place scanner.py in the project folder.



Create templates and static subfolders:

mkdir templates static



Add a basic index.html in templates (example below, or use your custom UI):

<!DOCTYPE html>
<html>
<head>
  <title>AD Scanner</title>
</head>
<body>
  <h1>Active Directory Scanner</h1>
  <button onclick="startScan()">Start Scan</button>
  <div id="progress"></div>
  <script>
    async function startScan() {
      const ws = new WebSocket('ws://localhost:8000/ws');
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        document.getElementById('progress').innerText = JSON.stringify(data, null, 2);
      };
      ws.onopen = () => {
        ws.send(JSON.stringify({
          scan: {
            ad_config: {
              server: 'ldap://your-ldap-server',
              username: 'user@domain.com',
              password: 'your-password',
              domain: 'your.domain.com',
              netbios_domain: 'YOURDOMAIN',
              port: 389,
              disable_ssl_verify: true
            },
            workstations_ou: 'OU=Workstations,DC=your,DC=domain,DC=com',
            servers_ou: 'OU=Servers,DC=your,DC=domain,DC=com',
            admin_groups: ['Administrators', 'Администраторы'],
            show_domain_names: true,
            recursive: true,
            no_duplicates: true,
            save_path: 'results'
          }
        }));
      };
    }
  </script>
</body>
</html>



Configure the Script:





Update the index.html script section with your AD configuration (LDAP server, credentials, domain, OUs, etc.).



Ensure the save_path directory (e.g., results) is writable.

Running the Script





Start the Server:





Navigate to the project folder in a terminal:

cd path/to/ad_scanner



Run the script:

python scanner.py



The server will start at http://127.0.0.1:8000.



Access the Web Interface:





Open a web browser and navigate to http://127.0.0.1:8000.



Click the "Start Scan" button to initiate a scan (based on the configuration in index.html).



Monitor Results:





Scan progress will be displayed in the browser (via WebSocket updates).



Results will be saved in the results folder as JSON and CSV files (e.g., local_admins_20250610_115254.json, local_admins_20250610_115254.csv).



Check scan.log in the project folder for detailed logs.

Output Files





JSON:





Contains scan results with computers, groups, and members.



Example structure:

[
  {
    "computer": "COMP1",
    "groups": {
      "Administrators": {
        "name": "Administrators",
        "sid": "S-1-5-32-544"
      }
    },
    "members": [
      {
        "type": "user",
        "domain": "YOURDOMAIN",
        "name": "YOURDOMAIN\\user1",
        "sid": "S-1-5-21-...",
        "is_domain": true,
        "description": "",
        "display_name": "User One",
        "from_group": "YOURDOMAIN\\Administrators",
        "path": "WinNT://YOURDOMAIN/user1",
        "domain_and_username": "YOURDOMAIN\\user1"
      }
    ]
  }
]



CSV:





Contains tabular data with columns: Computer, Group, Account, Domain, Type, SID, Description, DisplayName.



Uses ; as the delimiter and UTF-8 encoding for non-ASCII characters.

Troubleshooting





Missing 'domain' Error:





Ensure the ad_config in index.html includes a valid domain field (e.g., your.domain.com).



Check scan.log for details.



CSV/JSON Save Errors:





Verify the save_path directory exists and is writable.



Check scan.log for specific error messages.



LDAP/WMI Connection Issues:





Confirm network access to the LDAP server and target computers.



Verify credentials have sufficient permissions.



WebSocket Issues:





Ensure the browser supports WebSockets and no firewall blocks port 8000.# adminaudit
