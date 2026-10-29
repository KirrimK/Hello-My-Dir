<#
    THIS MODULE CONTAINS FUNCTIONS RELATED TO PINGCASTLE V4.0.0.31

    Fix list:
    > A-DsHeuristicsLDAPSecurity        Function Resolve-ADsHeuristicsLDAPSecurity
    > A-DnsZoneAUCreateChild            Function Resolve-ADnsZoneAUCreateChild
    > A-RootDseAnonBinding              Function Resolve-ARootDseAnonBinding
    
#>
#region A-DsHeuristicsLDAPSecurity
Function Resolve-ADsHeuristicsLDAPSecurity {
    <#
        .SYNOPSIS
        Resolve the alert A-DsHeuristicsLDAPSecurity from PingCastle.

        .DESCRIPTION
        The purpose is to fix domains not having mitigation for CVE-2021-42291 not enabled

        .NOTES
        Version 01.02.00 (2026/10/29 - Creation)
    #>

    Param()

    # Prepare for eventlog
    Test-EventLog | Out-Null
    $LogData = @('Fixing dsHeuristics value')

    # Define the new default dSHeuristics value
    $NewValue = "00000000010000000002000000011"

    # Retrieve the object and the specific dsHeuristics attribute
    $ConfigPath = (Get-ADRootDSE).configurationNamingContext
    $TargetDN = "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigPath"
    $DsObject = Get-ADObject -Identity $TargetDN -Properties dsHeuristics

    # Check if the attribute is set, and update it if needed
    if ($DsObject.dsHeuristics) {
        $LogData += @('Current dSHeuristics value:', $($DsObject.dsHeuristics))
        $NewValue = $DsObject.dsHeuristics -replace '..$', '11'
    } else {
        $LogData += 'dSHeuristics is currently <not set> (Default behavior)'
    }

    # Update the attribute on the Active Directory object
    try {
        Set-ADObject -Identity $TargetDN -Replace @{dsHeuristics = $NewValue} -ErrorAction Stop
        $LogData += @('Updated dSHeuristics to:', $NewValue, ' ', '> Successfull <')
        $FlagRes = 'Info'
    }
    catch {
        $LogData += @('! FAILED !',' ','Error message from stack:',$Error[0].ToString())
        $FlagRes = 'Error'
    }

    # Sending log and leaving with proper exit code
    Write-ToEventLog $FlagRes $LogData
    Return $FlagRes
}
#endregion

#region A-DnsZoneAUCreateChild
Function Resolve-ADnsZoneAUCreateChild {
    <#
        .SYNOPSIS
        Resolve the alert A-DnsZoneAUCreateChild from PingCastle.

        .DESCRIPTION
        The purpose is to fix Authenticated Users having the right to create DNS records

        .NOTES
        Version 01.02.00 (2026/10/29 - Creation)
    #>

    Param()

    # Prepare for eventlog
    Test-EventLog | Out-Null
    $LogData = @('Fixing permissions on DNS Zones (remove AuthenticatedUsers from creating records and replace with DomainComputer)')

    # Get the Domain SID to locate well-known security groups safely
    $DomainSID = (Get-ADDomain).DomainSID.Value
    $AuthUsersNT = [System.Security.Principal.NTAccount]("NT AUTHORITY\Authenticated Users")
    $DomainComputersNT = [System.Security.Principal.NTAccount]::New((Get-ADGroup "$DomainSID-515").Name)

    # Define the specific access rights to grant to Domain Computers (matching standard default dynamic update rights)
    $CreateChildObject = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $InheritNone = [System.Security.AccessControl.InheritanceFlags]::None
    $AllowType = [System.Security.AccessControl.AccessControlType]::Allow

    # Query Active Directory for all DNS Zones (both DomainDnsZones and ForestDnsZones partitions)
    $DomainDnsZones = Get-ADObject -Filter "objectClass -eq 'dnsZone'" -SearchBase "DC=DomainDNSZones,$((Get-ADRootDSE).rootDomainNamingContext)" -SearchScope Subtree 2>$null
    $ForestDnsZones = Get-ADObject -Filter "objectClass -eq 'dnsZone'" -SearchBase "DC=ForestDNSZones,$((Get-ADRootDSE).rootDomainNamingContext)" -SearchScope Subtree 2>$null

    $DnsZones = & {
        $DomainDnsZones
        $ForestDnsZones
    }

    foreach ($Zone in $DnsZones) {
        $LogData += @('Processing Zone:', $($Zone.Name))
        
        # Load the current Access Control List (ACL) from the Active Directory object path
        $ADPath = "AD:\$($Zone.DistinguishedName)"
        $ACL = Get-Acl -Path $ADPath
        
        # 1. Remove "Authenticated Users" access rules
        $RulesToRemove = $ACL.Access | Where-Object { $_.IdentityReference -eq $AuthUsersNT }
        foreach ($Rule in $RulesToRemove) {
            $ACL.RemoveAccessRule($Rule)
            $LogData += @('  Removed rule for Authenticated Users')
        }
        
        # 2. Add "Domain Computers" access rule (Create All Child Objects)
        # The Guid 'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9' target represents the 'dnsNode' schema object type
        $DnsNodeSchemaGuid = [Guid]"e0fa1e8c-9b45-11d0-afdd-00c04fd930c9"
        
        $NewRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::New(
            $DomainComputersNT,
            $CreateChildObject,
            $AllowType,
            $DnsNodeSchemaGuid,
            $InheritNone,
            [Guid]::Empty
        )
        
        $ACL.AddAccessRule($NewRule)
        $LogData += @("  'Added Create Child Objects' rule for Domain Computers")
        
        # Commit changes back to Active Directory
        Set-Acl -Path $ADPath -AclObject $ACL
    }

    $LogData += '> Successfull <'
    $FlagRes = 'Info'

    # Sending log and leaving with proper exit code
    Write-ToEventLog $FlagRes $LogData
    Return $FlagRes
}
#endregion

#region A-RootDseAnonBinding
Function Resolve-ARootDseAnonBinding {
    <#
        .SYNOPSIS
        Resolve the alert A-RootDseAnonBinding from PingCastle.

        .DESCRIPTION
        The purpose is to ensure that Anonymous Binding on RootDse is not enabled

        .NOTES
        Version 01.02.00 (2026/10/29 - Creation)
    #>

    Param()

    # Prepare for eventlog
    Test-EventLog | Out-Null
    $LogData = @('Fixing msDS-Other-Settings DenyUnauthenticatedBind value')

    # Define the target object path
    $ConfigDN = (Get-ADRootDSE).ConfigurationNamingContext
    $ObjectPath = "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigDN"

    # Add the setting to the msDS-Other-Settings attribute
    Set-ADObject -Identity $ObjectPath -Add @{ "msDS-Other-Settings" = "DenyUnauthenticatedBind=1" }

    $LogData += '> Successfull <'
    $FlagRes = 'Info'

    # Sending log and leaving with proper exit code
    Write-ToEventLog $FlagRes $LogData
    Return $FlagRes
}
#endregion