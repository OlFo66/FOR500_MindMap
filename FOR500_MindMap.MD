---
title: Windows Forensics 2/2
markmap:
    colorFreezeLevel: 2
    initialExpandLevel: 2
---
## Registry Forensics
### Registry Essentials
#### System Hives
##### Info
- Files storing vital configuration data for the system.
Keeps configuration data on the OS, installed applications, installed hardware & user accounts.
Registry hives are loaded into memory up system boot and user login.
- MRUList (Most Recently Used) from SOFTWARE hive, list last opened document by different software (Word, Wireshark, etc.)
- Similar to FS, registry hives have unallocated space. It may help to identify deleted items by antiforensic tools and,
until it is eventually overwritten, can be recovered.
- Transaction logs files (\<HIVENAME\>.LOG1 & \<HIVENAME\>.LOG2) can contain information not yet committed to the registry hives.
It is important to take them into account when investigating the Registry.
##### Hunting
- In  %Windir%\System32\Config:
_ SAM: local account information including users & groups
_ SECURITY: System security information such as audit policy & scurity identifiers
_ SYSTEM: Configuration data for attached hardware devices & system services
_ SOFTWARE: Cofniguration data for installed applications, including the Windows OS
_ DEFAULT: Default settings such as environment variables.
Usually overridden with user configuration data from the NTUSER hive so typically uninteresting
#### Users Hives
##### Info
- Store large amounts of configuration data for applications & settings pertaining to each user account.
We should expect find:
_ cloud storage settings
_ file & folder interaction
_ application execution
_ internet activities
- "Last Write Time" is an important artifact. 
It is updated when a vuel is added, updated or deleted.
It is stored in UTC time zone, always.
- RID (Relative IDentifier): SID is a unique value to represent an object in Active Directory. 
RID is the incremental portion of the SID value. Once RID value is being used to generate a SID, it will not use again. Even after deleting an object from AD, it will not able to reclaim the RID value back.
##### Hunting
- %UserProfile%\NTUSER.DAT
The most dominent user hive containing most relevant user-related data.
- %UserProfile%\AppData\Local\Microsoft\Windows\UserClass.dat
Since Vista OS, serves as virtualized registry root in support of the UAC. Most important of these artifacts are Shellbags & muicache
#### Tool
- Zimmerman's Tool - ReCmd
- Zimmerman's Tool - Registry Explorer
#### Links
- [Registry Virtualization](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-virtualization)
- [Poweliks Malware](https://www.vmray.com/poweliks-fileless-malware-analysis/)
- [Inside the Registry - Mark Russinovich](https://learn.microsoft.com/en-us/previous-versions/cc750583(v=technet.10)?redirectedfrom=MSDN)
- [Flush strategies in the Windows regsitry](https://github.com/msuhanov/regf-samples/blob/master/8.1-unreconciled/Flush%20strategies%20in%20the%20Windows%20registry.md)
### User/Group Information Analysis
- Hives:
%Windir%\System32\Config\SAM
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
- It contains only information on local users. Domain accounts are located in Domain Controller.
Times in SAM are stored in UTC time zone
If a "Total Login" == 0 and "Last Login Time" != null means the account is a cloud-based account.
[Microsoft Accounts (Windows 10)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-microsoft-accounts)
### System Configuration Auditing
- Identify Microsoft OS version + some info (installation date ie):
SOFTWARE\Microsoft\Windows NT\CurrentVersion
SYSTEM\Setup\Source OS (Historical updates)
- Computer Name:
SYSTEM\\<CurrentControlSet\>\Control\ComputerName\ComputerName
FYI: identify the curentcontrol set by checking SYSTEM\Select -> Current
- System Time Zone:
SYSTEM\CurrentControlSet\Control\TimeZoneInformation
- Network Interfaces:
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
- Historical Network Connections:
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
- Network Profiles - First & Last Times Connected:
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles (Win7+)
SOFTWARE\Microsoft\WZSVC\Parameters\Interfaces\\{GUID} (XP)
_NameType Value =   6 (0x06) = Wired
_NameType Value =  23 (0x17) = VPN
_NameType Value =  71 (0x47) = Wireless
_NameType Value = 243 (0xF3) = Mobile Broadband
_Category VAlue = 0 = Public network
_Category VAlue = 1 = Private network (home)
_Category VAlue = 2 = Domain (managed corporate network)
- CapabilityAccessManager
SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore
NTUSER\Software\Microsoft\Windows\CurrentVersionCapabilityAccessManager\ConsentStore
May be interesting to identify a malware using WebCam,µphone, else
- Shutdown information
SYSTEM\\\<CurentControlSet\>\Control\Windows (Shutdown Time)
SYSTEM\\\<CurentControlSet\>\Control\Watchdog\Display (Shutdown count - XP)
### User Activity Analysis
- Windows Search History - Search bar
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
- Windows Search History - Cortana
%UserProfile%\AppData\Local\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\LocalState\DeviceSearchCache (win10 before build 1909)
%UserProfile%\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\DeviceSearchCache (win10 build 1909+)
%UserProfile%\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\DeviceSearchCache (win11)
- Typed Paths - Records path typed into explorer by the user
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\typedPaths
- RecentDocs - Records folders, files/files types opened by user
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
- Microsoft Office file MRU
NTUSER\Software\Microsoft\Office\\<VERSION\>\\<APPNAME\>\File MRU
VERSION = 10.0 -> OfficeXP
VERSION = 11.0 -> Office2003
VERSION = 12.0 -> Office2007
VERSION = 14.0 -> Office2010
VERSION = 15.0 -> Office2013
NTUSER\Software\Microsoft\Office\\<VERSION\>\\<APPNAME\>\User MRU\LiveID_####\File MRU
NTUSER\Software\Microsoft\Office\\<VERSION\>\\<APPNAME\>\User MRU\ADAL_####\File MRU
VERSION = 16.0 -> Office2016/2019/M365
- Trusted documents - (i.e: when user click on "Enable Content" in a excel macro)
NTUSER\Software\Microsoft\Office\\<VERSION\>\\<APPNAME\>\Security\Trusted Documents\TrustRecords
- Common Dialog Keys - Records location of last opened/saved files of specific types 
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy
## Application Execution
- BAM/DAM (Background/Desktop Activity Moderator):
SYSTEM\\<CurrentControlSet\>\Services\\(dam|bam\)\State\UserSettings\\{SID\}  (Since Win10 build 1709)
Provides fullpath of of the executable file & last execution date up to 1 week.
- Last command executed 
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU (command executed via taskbar)
- UserAssist
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
Provides ApplicationName, RunCount, FocusTime, LastRunTime 
- Task Bar FeatureUsage
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage (Since Win10 1903)
Provides information on application execution, pinned applications, #times the application was put into focus. 
Information stays even after application removal.
- Prefetch 
C:\Windows\Prefetch
Provides application execution data
- [How to Employ FeatureUsage for Win10 Taskbar Forensic](https://www.crowdstrike.com/en-us/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/)
- [Microsoft docs - KNOWNFOLDERID](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid)
## Cloud Storage Forensics
### Microsoft OneDrive (By default since Win8+)
#### Local Files
- %UserProfile%\OneDrive (default)
NTUSER\Software\Microsoft\OneDrive\Accounts\Personal (if custom)
#### Metadata
- %UserProfile%\AppData\Local\Microsoft\OneDrive\logs\Personal (exists only if OneDrive is enabled)
-> SyncDiagnotics.log - may provide information on local & cloud cloud files
-> ObfuscationStringMap.txt - may provide filenames present in OneDrive
%UserProfile%\AppData\Local\Microsoft\OneDrive\settings\Personal
### Microsoft OneDrive for Business
#### Local Files
- %UserProfile%\OneDrive - \<CompanyName\> (default)
NTUSER\Software\Microsoft\OneDrive\Accounts\Business1 (if custom)
#### Metadata
- %UserProfile%\AppData\Local\Microsoft\OneDrive\logs\Business1
-> SyncDiagnotics.log - may provide information on local & cloud cloud files
-> \<Usercid\>.dat - list of local & cloud file names
#### Links
- [Cloud Storage services](https://community.spiceworks.com/t/cloud-storage-services-who-claims-the-top-spot-among-microsoft-google-dropbox/970651)
[OneDriveExplorer](https://github.com/Beercow/OneDriveExplorer)
[Search the audit log in Security & Compliance Center](https://learn.microsoft.com/en-us/purview/audit-search?tabs=microsoft-purview-portal)
### Google Drive
#### Local Files
- NTUSER\Software\Google\DriveFS\Share - Contains the local drive letter used
%UserProfile%\AppData\Local\Google\DriveFS\\<account identifier\>\content_cache - Contains file cache
#### Metadata
- %UserProfile%\AppData\Local\Google\DriveFS\<account identifier\>
-> metadata_sqlite_db - contains a list of offline, cloud-only & deleted files present
#### Links
- [Protocol Buffer](https://protobuf.dev/)
### DropBox
#### Local Files
- %UserProfile%\Dropbox (default)
%UserProfile%\Dropbox\.dropbox.cache (up to 3 days of deleted & staged files)
#### Metadata
- %UserProfile%\AppData\Local\Dropbox\
-> nucleus.sqlite3, sync_histor.db & aggregation.dbx - provide usage data & metadata for local, cloud & deleted files
## Shell Item Analysis
### Recent Items LNK Files
#### Hunting
- C:\Users\\<UserName\>\AppData\Roaming\Microsoft\Office\Recent (Win7+)
C:\Users\\<UserName\>\AppData\Roaming\Microsoft\Windows\Recent (Win7+)
C:\Document and Sttings\\<UserName\>\Recent (WinXP)
#### Tool
- [Eric Zimmerman's tool LECmd](https://ericzimmerman.github.io/#!index.md)
#### Links
- [Shell link (LNK) binary file format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)
[Introducing LECmd by Eric Zimmerman](https://binaryforay.blogspot.com/2016/02/introducing-lecmd.html)
### Jump List Artifacts
#### Hunting
- C:\Users\\<UserName\>\AppData\Roaming\Microsoft\Windows\Recetn\AutomaticDestinations
C:\Users\\<UserName\>\AppData\Roaming\Microsoft\Windows\Recetn\CustomDestinations
#### Tool
- [Zimmerman's Tool JLECmd](https://ericzimmerman.github.io/#!index.md)
#### Links
- [CustomDestinationList interface - Microsoft](https://learn.microsoft.com/en-gb/windows/win32/api/shobjidl_core/nn-shobjidl_core-icustomdestinationlist?redirectedfrom=MSDN)
[OLE Compound File](https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc)
[Jump list in depth](https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html)
[ICustomDestinationList interface](https://learn.microsoft.com/en-gb/windows/win32/api/shobjidl_core/nn-shobjidl_core-icustomdestinationlist?redirectedfrom=MSDN)
[JumpList files names & AppID calculator](https://www.hexacorn.com/blog/2013/04/30/jumplists-file-names-and-appid-calculator/)
[Zimmerman's JumpList AppIDs.txt file](https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt)
[Forensics Wiki Jump List ID](https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt)
[JumplList Class - Microsoft docs](https://learn.microsoft.com/en-us/uwp/api/windows.ui.startscreen.jumplist?view=winrt-22000)
### ShellBags
#### Hunting
- Win7+:
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
- WinXP:
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\Bags
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU
#### Links
- [Using shellbag information to reconstruct user activities](https://www.sciencedirect.com/science/article/pii/S1742287609000413)
[Windows 10 Feature Updates](https://df-stream.com/2019/10/shellbags-windows-10-feature-updates/)
[Windows ShellBags Forensics](https://www.sans.org/white-papers/34545/)
[Zimmerman's GuidMapping Document](https://github.com/EricZimmerman/GuidMapping/blob/master/Resources/GuidToName.txt)
#### Tools
- [Zimmerman's SBECmd](https://ericzimmerman.github.io/#!index.md)
## USB Device Analysis
### Hunting
- SYSTEM\\<CurrentControlSet\>\Enum\HID
SYSTEM\\<CurrentControlSet\>\Enum\USB
SYSTEM\\<CurrentControlSet\>\Enum\USBSTOR
SYSTEM\\<CurrentControlSet\>\Enum\SCSI
SOFTWARE\Microsoft\Windows Portabe Devices
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache (Win7+)
SYSTEM\MountedDevices
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
- Evtx
 20001,20003 - Plug & Play driver installe attemped (System log)
 4663 - Attempt to access removal storage object (Security log)
 4656 - Failure to access removal storage object (Security log)
 6416 - A new external device was reconized on system (Security log)
 1006 - Device connect/disconnect (Windows Partition/Diagnostic log)
### Tools
- [Zimmerman's RegExplorer](https://ericzimmerman.github.io/#!index.md)
[USB Detective Tool](https://usbdetective.com/)
[USBDeviceForensics Tool GitHub](https://github.com/woanware/usbdeviceforensics)
### Links
- [The rise of Evil HID devices](https://www.youtube.com/watch?v=6xD1XYBArMY)
[HID usage Tables](https://www.usb.org/document-library/hid-usage-tables-15)
[CIRCL Forensic Analysis of an HID Attack](https://www.circl.lu/pub/tr-52/)
[Media Transfert Protocol](https://en.wikipedia.org/wiki/Media_Transfer_Protocol)
[USB IDs Repository](https://www.linux-usb.org/usb.ids)
[Device Hunt](https://devicehunt.com/)
[Harware ID - Microsoft Docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hardware-ids)
[Windows IR](https://windowsir.blogspot.com/2013/01/there-are-four-lights-usb-accessible.html)
## Email Forensics
### Host-Based Email forensics
#### µSoft Outlook
##### Hunting
- %UserProfile%\Documents\Outlook (Default Storage)
%UserProfile%\AppData\Local\Microsoft\Outlook (Default Storage)
NTUSER\Software\Microsoft\Office\16.0\Outlook\Search (Identify other archives)
 .OST (Office Outlook Data File): M365, Exchange, IMAP
 .PST (Outlook Data File): POP accounts, archives, older installation
 .NST (Outlook Group Storage File): Group convesations & calendar
 %UserProfile%\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook (Outlook Attachment - Default)
 NTUSER\Sfotware\Microsoft\Office\\<version\>\Outlook\Security (Outlook Attachment - Configuration)
##### Links
- [NirSoft Mail Pass](https://www.nirsoft.net/utils/mailpv.html)
[Outlook Personal Forlder](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546?redirectedfrom=MSDN)
[Kernel PST viewer](https://www.nucleustechnologies.com/pst-viewer.html)
[Kernel OST viewer](https://www.nucleustechnologies.com/ost-viewer.html)
[PST Walker - Email Recovery and Migration](https://www.pstwalker.com/)
### Server-Based Email forensics
#### µSoft Exchange
##### Hunting
- `New-MailboxExportRequest -Mailbox <mailbox> -FilePAth \\PATH\TO\mailbox.pst` PowerShell command to export mail since Exchange 2010 SP1
- `New-MailboxExportRequest -Mailbox <mailbox> - ContentFilter {(body -like "Something") -and (Received -lt "MM/DD/YYY")} -FilePAth \\PATH\TO\mailbox.ps` Filter example
##### Links
- [File Structure of Exchange Store](https://learn.microsoft.com/en-us/previous-versions/office/exchange-server-2007/bb331964(v=exchg.80)?redirectedfrom=MSDN)
[Recoverable Items Folder](https://learn.microsoft.com/en-us/exchange/security-and-compliance/recoverable-items-folder/recoverable-items-folder)
[Single Item Recovery in Exchange](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-user-mailboxes/change-deleted-item-retention)
#### µSoft 365
##### Hunting
- `Search-UnifiedAuditLog -StartDate MM/DD/YYYY -EdnDate MM/DD/YYYY -UserIds <user1, user2> -Operations MailItemsAccessed` - Unified Audit Logs in µSoft 365
##### Links
- [Use Content Search in your eDiscovery](https://learn.microsoft.com/en-gb/purview/ediscovery-content-search?redirectSourcePath=%252fen-us%252farticle%252fuse-content-search-in-your-ediscovery-workflow-55f31488-288a-473a-9b9e-831a11e3711a)
[Use Compliance Search to Search All Mailboxes in Exchange](https://learn.microsoft.com/en-us/exchange/policy-and-compliance/ediscovery/compliance-search?view=exchserver-2019&redirectedfrom=MSDN)
[Run a Content Search in µSoft 365 Security & Compliance Center](https://learn.microsoft.com/en-gb/purview/ediscovery-content-search?redirectSourcePath=%252fen-us%252farticle%252frun-a-content-search-in-the-office-365-security-compliance-center-61852fd9-fe8a-4880-a339-cb19ed3bff4a#create)
[Export content Search Result from µSoft 365](https://learn.microsoft.com/en-gb/purview/ediscovery-export-search-results?redirectSourcePath=%252fen-us%252farticle%252fexport-content-search-results-from-the-office-365-security-compliance-center-ed48d448-3714-4c42-85f5-10f75f6a4278)
[µSoft 365 - Manage MailBox Auditing](https://learn.microsoft.com/en-ie/purview/audit-mailboxes#mailbox-auditing-actions)
[Investigate an Activity in µSoft 365 Cloud App Security](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy)
[Search-UnifiedAuditLog (ExchangePowerShell)](https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog?view=exchange-ps)
[Office 365 Extractor](https://github.com/PwC-IR/Office-365-Extractor)
## Additional Windows Artifacts
### Windows Search Database
- C:\ProgramData\Microsoft\Searech\Data\Application\Windows\Windwis.edb (Win7+ )
C:\Documents and Settings\All Users\Application Data\Microsoft\Search\Data\Applications\Windows\Windiws.edb
[Troubleshoot Windows Search performance - Microsocft docs](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/windows-search-performance-issues)
[Search indexing in Windows 10: FAQ](https://support.microsoft.com/en-us/windows/search-indexing-in-windows-faq-da061c83-af6b-095c-0f7a-4dfecda4d15a)
[Configuration and Settings](https://devblogs.microsoft.com/windows-search-platform/configuration-and-settings/)
[ESE NT Utilities](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875546(v=ws.11))
[WinSearchDBAnalyzer 1/2](https://github.com/moaistory/WinSearchDBAnalyzer)
[WinSearchDBAnalyzer 2/2](https://moaistory.blogspot.com/2018/10/winsearchdbanalyzer.html)
### Windows Search Gather Logs
- C:\ProgramData\Microsoft\Search\Data\Applicatinos\Windows\GatherLogs\SystemIndex
Evidence of:
Intersting files
File changes
Deleted or wiped files
### Windows Thumbcache
- C:\Users\\<UserName\>\AppData\Local\Microsoft\Windows\Explorer
[Thumbcache Viewer](https://thumbcacheviewer.github.io/)
[Thumbs.db Viewer](https://thumbsviewer.github.io/)
[Win7 Thumbcache hash algorithm](https://www.swiftforensics.com/2012/06/windows-7-thumbcache-hash-algorithm.html)
### RecycleBin forensics
- C:\$RECYCLE.BIN\\<User SID\>\$Ixxxxx (Win7+)
C:\RECYCLER\\<User SID\>\INFO2 (WinXP)
[Zimmerman's RBCmd](https://ericzimmerman.github.io/#!index.md)
### Win10+ Timeline details
- C:\Users\\<UserName\>\AppData\Local\ConnectedDevicesPlatform\\<SomeThing\>\ActivitiesCache.db
NTUSER.DAT\Software\Microsoft\IdentityCRL\UserExtendedProperties (Cross-referenced local account name <-> Microsoft Cloud Account)
Logs 30+ days of User Activity:
App execution
File opening
URL visited
Time Zones
User removed items persist in the database
NTUSER.DAT/Software/Microsoft/Windows/CurrentVersion/TaskFlow/DeviceCache - List of assets timeline is synced with.
DeviceType:
1: XboxOne
6: Apple iPhone
7: Apple iPad
8: Android device
9: Windows 10 Desktop
11: Windows 10 Phone
12: Linux device
13: Windows IoT
14: Microsoft Surface Hub
15: Windows 10 Laptop
16: Windows Surface
[Exploring the Windows activity Timeline (Part 1) - Vico Marziale](https://cellebrite.com/en/exploring-the-windows-activity-timeline-part-1-the-high-points/)
[Exploring the Windows activity Timeline (Part 2) - Vico Marziale](https://cellebrite.com/en/exploring-the-windows-activity-timeline-part-2-syncing-across-devices/)
[Kacos2000 WinTimelineLocal.ps1 script](https://github.com/kacos2000/WindowsTimeline/blob/master/WinTimelineLocal.ps1)
[Connected Devices Platform Protocol v3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/f5a15c56-ac3a-48f9-8c51-07b2eadbe9b4)
[Zimmerman's WxTCmd.exe](https://ericzimmerman.github.io/#!index.md)
### SRUM - System Resource Usage Monitoring
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions
C:\Windows\System32\SRU\
[ESE Database View](https://www.nirsoft.net/utils/ese_database_view.html)
[NirSoft Network Usage View](https://www.nirsoft.net/utils/network_usage_view.html)
[SRUM_DUMP](https://github.com/MarkBaggett/srum-dump)
[SrumMonkey](https://github.com/devgc/SrumMonkey)
[Zimmerman's SrumECmd](https://ericzimmerman.github.io/#!index.md)
## Event Log Analysis
### Microsoft Office OAlerts
- OAlerts.evtx Code 300
Identify file interaction and alerts generated by Microsoft Office.
[OAlerts - The Microsoft Office Event log](https://bromiley.medium.com/oalerts-the-microsoft-office-event-log-ad164e1eec0f)
### Wireless Network Geolocation
- Microsoft-Windows-WLAN-AutoConfig Operational.evtx
8001 - Sucessful connection to wireless network
8002 - Failed connection to wireless network
8003 - Disconnection from wieless network
11004 - Wireless security stopped
11005 - Wireless security succeeded
## Browser Forensics
### Google Chrome
#### Info
- %UserProfile%\AppData\Local\Google\Chrome\User Data (Win7+)
%UserProfile%\Local Settings\Applicatin Data\Google\Chrome\User Data(WinXP)
- Artifacts stored in the following formats:
   SQLite (majority of artifacts)
   JSON
   SNSS (session saver files)
#### History
- %UserProfile%\AppData\Local\Google\Chrome\User Data\\<Profile\>
   History
   Archived History
   History Index YYYY-MM
   Top sites
#### Cache
- %UserProfile%\AppData\Local\Google\Chrome\User Data\\<Profile\>\Cache
   Filename
   URL
   Content Type
   File Size
   Last Fetched Time
   Server Time
#### Cookies
- %UserProfile%\AppData\Local\Google\Chrome\User Data\\<Profile\>\Network
#### HTML5 Web Storage
- %UserProfile%\AppData\Local\Google\Chrome\User Data\\<Profile\>\Local Storage\
#### HTML5 FileSystem
- %UserProfile%\AppData\Local\Google\Chrome\User Data\\<Profile\>\File System\
To be used in conjunction with LevelDB database from "Local Storage" folder.
Provides correlation between information found in LevelDB and an artifact in the FS.
#### Shortcuts
- %UserProfile%\AppData\Local\Google\Chrome\User Data\\<Profile\>\
Provides information on browsed websites
#### Session Recovery
- %UserProfile%\AppData\Local\Google\Chrome\User Data\\<Profile\>\Sessions
Provides information on browsed websites
#### Chrome syncrhonization
- History
    Only typed URLs
    Visit count, typed count
    Visit time
Web Data
BookMarks
Extensions
Login Data
Tabs
### Microsoft Edge
- %UserProfile%\AppData\Local\Microsoft\edge\User Data\\<Profile\>\
As Edged is Chromium based, most artifacts are similar.
Few differences exist, not described here.
### Mozilla Firefox
- %UserProfile%\AppData\Roaming\Mozilla\Firefox\Profiles\\<random text\>.default ( History, Cookies, Bookmarks, AutoCompletion)
- %UserProfile%\AppData\Local\Mozilla\Firefox\Profiles\\<random text\>.default\Cache - Cache
SQLite format
### Links
- [Page Transition](https://kb.digital-detective.net/display/BF/Page+Transitions)
- [Deciphering Browser Hieroglyphics](https://dfir.blog/deciphering-browser-hieroglyphics-leveldb-filesystem/)
### Tools
- [NirSoft ChromeChacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)
- [LevelDB-py](https://github.com/markmckinnon/Leveldb-py)
- [ChromeStorageDump](https://github.com/rdreher/chromeStorageDump)
- [Hindsights !!!](https://github.com/obsidianforensics/hindsight)
- [Nirsoft MZCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)