#!/usr/bin/env python3
"""
Generate a sample report with realistic mock data.
No BloodHound connection or .env required.

Usage:
    python test_report.py
"""

from checks import CheckResult
from report.renderer import write_report
from pathlib import Path

DOMAIN = "CORP.LOCAL"

SAMPLE_RESULTS = [
    CheckResult(
        check_id="outbound_control",
        title="Outbound Object Control",
        description=(
            "Lists every object that the large default groups "
            "(Everyone, Authenticated Users, Domain Users, Domain Computers) "
            "have direct control over, along with the specific permission and "
            "target object type."
        ),
        headers=["Source Group", "Permission", "Target Object", "Target Type", "Status"],
        rows=[
            ["EVERYONE@CORP.LOCAL", "GenericAll", "YOURPC01.CORP.LOCAL", "Computer", "Enabled"],
            ["EVERYONE@CORP.LOCAL", "WriteDacl", "IT-HELPDESK@CORP.LOCAL", "Group", ""],
            ["AUTHENTICATED USERS@CORP.LOCAL", "WriteOwner", "FILE-SRV02.CORP.LOCAL", "Computer", "Enabled"],
            ["AUTHENTICATED USERS@CORP.LOCAL", "GenericWrite", "SVC_BACKUP@CORP.LOCAL", "User", "Enabled"],
            ["AUTHENTICATED USERS@CORP.LOCAL", "WriteDacl", "PRINT-SRV01.CORP.LOCAL", "Computer", "Enabled"],
            ["DOMAIN USERS@CORP.LOCAL", "ForceChangePassword", "J.SMITH@CORP.LOCAL", "User", "DISABLED"],
            ["DOMAIN USERS@CORP.LOCAL", "GenericAll", "LEGACY-DC01.CORP.LOCAL", "Computer", "Enabled"],
            ["DOMAIN USERS@CORP.LOCAL", "AddMember", "VPN-USERS@CORP.LOCAL", "Group", ""],
            ["DOMAIN USERS@CORP.LOCAL", "WriteDacl", "GPO-WORKSTATIONS@CORP.LOCAL", "GPO", ""],
            ["DOMAIN COMPUTERS@CORP.LOCAL", "ReadLAPSPassword", "WS-PC042.CORP.LOCAL", "Computer", "Enabled"],
            ["DOMAIN COMPUTERS@CORP.LOCAL", "GenericAll", "CERT-SRV01.CORP.LOCAL", "Computer", "Enabled"],
        ],
        severity="high",
    ),
    CheckResult(
        check_id="kerberoastable",
        title="Kerberoastable Users",
        description=(
            "User accounts with a Service Principal Name (SPN) set. "
            "These accounts are vulnerable to offline password cracking "
            "via Kerberoasting. Prioritise accounts with admincount=true."
        ),
        headers=["User", "Description", "Admin Count"],
        rows=[
            ["SVC_SQL@CORP.LOCAL", "SQL Server service account for production DB cluster", "Yes"],
            ["SVC_SCCM@CORP.LOCAL", "SCCM primary site service account", "Yes"],
            ["SVC_BACKUP@CORP.LOCAL", "Veeam backup service — scheduled nightly", "No"],
            ["SVC_IIS@CORP.LOCAL", "IIS application pool identity for intranet", "No"],
            ["SVC_EXCHANGE@CORP.LOCAL", "Exchange transport service", "No"],
            ["SVC_SHAREPOINT@CORP.LOCAL", "SharePoint farm account", "No"],
            ["KRBTGT_OLD@CORP.LOCAL", "Legacy Kerberos service (decomm pending)", "No"],
        ],
        severity="high",
    ),
    CheckResult(
        check_id="asrep_roastable",
        title="AS-REP Roastable Users",
        description=(
            "User accounts that do not require Kerberos pre-authentication. "
            "An attacker can request an AS-REP for these accounts without "
            "credentials and crack the response offline."
        ),
        headers=["User", "Description"],
        rows=[
            ["T.LEGACY@CORP.LOCAL", "Contractor account — legacy app compatibility"],
            ["SVC_OLDAPP@CORP.LOCAL", "Service account for retired COBOL bridge"],
        ],
        severity="high",
    ),
    CheckResult(
        check_id="large_group_admin",
        title="Large Groups with Admin Rights",
        description=(
            "Groups with a large membership that hold local administrator "
            "rights on one or more computers. This means hundreds of users "
            "potentially have admin access, dramatically increasing risk."
        ),
        headers=["Group", "Description", "Members", "Admin On # Computers"],
        rows=[
            ["DOMAIN USERS@CORP.LOCAL", "All domain user accounts", "4521", "37"],
            ["AUTHENTICATED USERS@CORP.LOCAL", "All authenticated identities", "4953", "12"],
            ["IT-ALL-STAFF@CORP.LOCAL", "All IT department staff", "312", "8"],
        ],
        severity="critical",
    ),
]


def main():
    path = write_report(DOMAIN, SAMPLE_RESULTS, Path("./reports"))
    print(f"Sample report written to: {path}")
    print(f"Open it in your browser:  file://{path.resolve()}")


if __name__ == "__main__":
    main()
