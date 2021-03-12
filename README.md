<img align="center" src="/images/PIE-Logo.png" width="125px" alt="PIE">

    Phishing Intelligence Engine
    v4.0  --  February, 2021

Copyright 2021 LogRhythm Inc. - See licensing details below

- [[About]](#about)
    + [Features:](#features)
- [[Additional Information]](#additional-information)
- [[Install and Usage]](#install-and-usage)
  * [[Requirements]](#requirements)
- [[Thanks!]](#thanks!)
  * [[PIE v3 Contributors]](#pie-v3-contributors)
  * [[Additional Contributions]](#additional-contributions)
- [[Lead Author]](#lead-author)
- [[License]](#license)

## [About]
    
![Phishing Intelligence Engine](/images/PIE.png)

The Phishing Intelligence Engine (PIE) is a framework built around evaluating e-mail messages submitted as suspicious messages within your organization, PIE evaluates e-mail contents for malicious contents, and dynamically establishes content to enable and accelerate threat qualification and scope.

##### :rotating_light: This framework is not officially supported by LogRhythm  :rotating_light:

#### Features:

  - Analyze subjects, headers, embedded links, and file attachments
  - Identify all recipients of e-mail messages from a reported sender
  - Automated submission of URL, IP Addresses, and file hashes to third party analytic services
  - Dynamic Case Management integration and metrics tracking


**PIE 4.0 has been re-written with focus on:**

  1. Reduced setup and configuration complexity
     * No longer requires use of Outlook application
     * No longer requires Microsoft 365 service account
     * Requires no privileged access account(s)
     * Automated e-mail inbox folder setup
     * Automated PIE folder management for tmp, case, and logging
  
  2. Expand module availability
     * PIE is now supports working with any mail service provider that supports IMAP client connectivity
  
  3. Expanded use of LogRhythm API use
     * Able to leverage the LogRhyhtm Search API to identify message delivery results associated with the e-mail analysis
     * Log results enriched into the LogRhythm Case to accelerate investigation
     * LogRhythm's TrueIdentity service provides enriched details on initial e-mail sender and recipient
     * Apply multiple case tags and/or playbooks to enabling improved reporting and SOC investigation management
     * Earliest Evidence metrics populated to ensure Mean Time to Detect and Mean Time to Respond metrics are consistently available
  
  4. Improved processing logic
     * Dedicated pipelines have been established to enable optimal processing and facilitate easier scale and project growth
  
  5. Improved runtime diagnostics
     * Runtime metrics captured for every email analyzed
     * Additional details and error handling provided in the PIE runlog
  
   6. Improved case content quality
     * PIE Analysis Summary
     * URL and Attachment Summary
     * Header Analysis Summary
     * Search Result Summary
  
  7. Additional evidence output content
     * A complete analysis json object file is now available to enable additional integrations
     * Case report updated to reflect same content provided in LogRhythm Case
     * LogRhythm search results are exported to csv
  
  8. New inspection methods
     * A new header inspection process is included to summarize and provide header details

## [Additional Information]

The Phishing Intelligence Engine 4.0 is built on top of LogRhythm.Tools.  As a part of installing and leveraging PIE it is now required for LogRhythm.Tools to be installed prior to implementing PIE.

For information on LogRhythm.Tools and detailed steps on how to install, access the LogRhythm.Tools Project here:
https://github.com/LogRhythm-Tools/LogRhythm.Tools

To download the latest LogRhythm.Tools release package, visit:
https://github.com/LogRhythm-Tools/LogRhythm.Tools/releases


## [Install and Usage]

### [Requirements]

1. System requirements:
    -	Windows Server: 2019, 2016, 2012 R2
    - CPU: 2 Cores
    -	RAM: 8 GB
    -	OS Drive: 100 GB
    -	Data Drive: 100 GB
    -	Software: 
        - Microsoft .Net 4.5
        -	PowerShell v5.1

2. A dedicated e-mail inbox that receives submitted suspicious e-mail messages with the original e-mail message provided as a .eml or .msg attachment.
   
3. The dedicated e-mail inbox must be configured to support IMAP e-mail client connectivity.

4. Installation of LogRhythm.Tools PowerShell Module.
   

## [Thanks!]

This project would not be a success without the folks below and the various third-party API integration providers. Thank you!

**Creator and former lead author of PIE.**
- [Greg Foss](https://github.com/gfoss) - formerly of LogRhythm Labs.

### [PIE v3 Contributors]
- bruce deakyne -  Cisco AMP Threat GRID Plugin
- Gewch, LogRhythm Community - Special character handler in e-mail subject line and updated ShortLink parser
- jake reynolds - OpenDNS Plugin
- julian crowley - Message Tracking Log Parsing
- matt willems - LogRhythm Case API Plugin
- sslawter, LogRhythm Community - PIE Message Trace enhancements
- zack rowland - Outlook Button
- SwiftOnSecurity - Phishing RegEx

### [Additional Contributions]
- shaunessy o'brien - PIE Logo
- steve warburton - User Acceptance Testing


## [Lead Author]

[Eric Hart](https://github.com/Jtekt) - LogRhythm - Technical Account Manager


## [License]

Copyright 2021 LogRhythm Inc.   

PowerShell code is Licensed under the MIT License. See LICENSE file in the project root for full license information.

LogRhythm integrated code (SmartResponse and Dashboards) is licensed pursuant to the LogRhythm End User License Agreement located at https://logrhythm.com/about/logrhythm-terms-and-conditions/ (“License Agreement”) and by downloading and using this content you agree to the terms and conditions of the License Agreement unless you have a separate signed end user license agreement with LogRhythm in which case that signed agreement shall govern your licensed use of this content. For purposes of the applicable end user license agreement, this content constitutes LogRhythm Software
