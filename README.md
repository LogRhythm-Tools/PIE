<img align="center" src="/images/PIE-Logo.png" width="125px" alt="PIE">

    Phishing Intelligence Engine
    v4.0  --  February, 2021

Copyright 2021 LogRhythm Inc. - See licensing details below

## [About]
    
![Phishing Intelligence Engine](/images/PIE.png)

The Phishing Intelligence Engine (PIE) is a framework built around evaluating e-mail messages submitted as suspicious messages within your organization, PIE evaluates e-mail contents for malicious contents, and dynamically establishes content to enable and accelerate threat qualification and scope.

##### :rotating_light: This framework is not officially supported by LogRhythm  :rotating_light:

#### Features:

  - Analyze subjects, headers, embedded links, and file attachments
  - Identify all recipients of e-mail messages from a reported sender
  - Automated submission of URL, IP Addresses, and file hashes to third party analytic services
  - Dynamic Case Management integration and metrics tracking


#### 4.0 Updates:

**PIE has been re-written with focus on:**

  1. Reduced setup and configuration complexity
  * Automated e-mail inbox folder setup
  * Automated PIE folder management for tmp, case, and logging
  * No longer requires use of Outlook application
  * No longer requires Microsoft 365 service account
  * Requires no priviledged accesss account(s)
  
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
  * Runtime metrics captured for every analysis
  * Additional details and error handling provided in the PIE runlog
  
   6. Improved case content quality
  * PIE Analysis Summary
  * URL and Attachment Summary
  * Header Analysis Summary
  * Search Result Summary
  
  7. Additional evidence output content
  * LogRhythm search results are exported to csv
  * A complete analysis json object file is now available to enable additional integrations
  * Case report updated to reflect same content provided in LogRhythm Case
  
  8. New inspection methods
  * A new header inspection process is included to provide and summarize header details



## [Additional Information]

LogRhythm.Tools: https://github.com/LogRhythm-Tools/LogRhythm.Tools


## [Install and Usage]



## [Thanks!]

This project would not be a success without the folks below and the various third-party API integration providers. Thank you!

**Initial author and creator of PIE.**
- [Greg Foss](https://github.com/gfoss) - formerly of LogRhythm Labs.  

### [PIE v3 Contributors]
- bruce deakyne -  Cisco AMP Threat GRID Plugin
- Gewch, LogRhythm Community - Special character handler in e-mail subject line and updated ShortLink parser
- jake reynolds - OpenDNS Plugin
- julian crowley - Message Tracking Log Parsing
- matt willems - LogRhythm Case API Plugin
- shaunessy o'brien - PIE Logo
- sslawter, LogRhythm Community - PIE Message Trace enhancements
- steve warburton - User Acceptance Testing
- zack rowland - Outlook Button
- SwiftOnSecurity - Phishing RegEx


## [Lead Author]

[Eric Hart](https://github.com/Jtekt) - LogRhythm Technical Account Manager


## [License]

Copyright 2021 LogRhythm Inc.   

PowerShell code is Licensed under the MIT License. See LICENSE file in the project root for full license information.

LogRhythm integrated code (SmartResponse and Dashboards) is licensed pursuant to the LogRhythm End User License Agreement located at https://logrhythm.com/about/logrhythm-terms-and-conditions/ (“License Agreement”) and by downloading and using this content you agree to the terms and conditions of the License Agreement unless you have a separate signed end user license agreement with LogRhythm in which case that signed agreement shall govern your licensed use of this content. For purposes of the applicable end user license agreement, this content constitutes LogRhythm Software
