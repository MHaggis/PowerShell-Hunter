<#
.SYNOPSIS
Configuration file for AD-ThreatHunting module

.DESCRIPTION
Contains thresholds, patterns, and settings for AD threat detection.
Modify these values based on your environment's baseline.

.NOTES
Author: The Haag
Last Updated: 2024-12-20
#>

@{
    # Event IDs to monitor
    EventIDs = @{
        AccountLockout = '4740'
        FailedLogin = '4625'
        SuccessfulLogin = '4624'
        PasswordChange = '4723'
        AccountModification = '4738'
    }

    LogonTypes = @{
        '2' = 'Interactive'
        '3' = 'Network'
        '4' = 'Batch'
        '5' = 'Service'
        '7' = 'Unlock'
        '8' = 'Networkcleartext'
        '9' = 'NewCredentials'
        '10' = 'RemoteInteractive'
        '11' = 'CachedInteractive'
    }

    # Thresholds for suspicious activity
    Thresholds = @{
        PasswordSprayThreshold = 3
        FailedLoginsPerHour = 3
        LockoutThreshold = 3
    }

    # Time windows for suspicious activity
    TimeWindows = @{
        PasswordSprayWindow = 5
        BruteForceWindow = 60
    }

    # Known patterns
    Patterns = @{
        ServiceAccounts = @(
            'svc_*'
            'service_*'
        )
        AdminAccounts = @(
            'admin_*'
            'adm_*'
        )
        PrivilegedGroups = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Account Operators'
        )
    }

    TimingThresholds = @{
        HighActivityThreshold = 30    # Number of attempts in 5 minutes to consider high activity
        BruteForceRateThreshold = 10  # Attempts per minute to consider brute force
        SprayTimeWindow = 5           # Minutes to group attempts for spray detection
    }

    AdvancedThreats = @{
        # Business hours (24-hour format)
        BusinessHours = @{
            Start = 9  # 9 AM
            End = 17   # 5 PM
        }
        
        # Unusual login hours (outside business hours)
        UnusualLoginHours = @(0,1,2,3,4,5,6,22,23)  # 10PM-6AM
        
        # Workstation patterns for IT/Admin use
        ITWorkstations = @(
            'IT-*',
            'ADMIN-*',
            'HELPDESK-*'
        )

        # Time threshold for geographically impossible logins (in seconds)
        GeographicallyImpossibleLoginSeconds = 300  # 5 minutes
        
        # Whether to alert on admin account usage outside IT workstations
        AdminAccountUsageOutsideIT = $true
    }
} 