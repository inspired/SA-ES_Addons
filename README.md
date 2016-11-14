# SA-Datametrix_ES_Addons
Datametrix ES Add-ons

## Contents
### Correlation searches
* Correlation search that creates a notable event for blocked USB devices connected to endpoints. Tested with the Symantec Endpoint Protection app but should work regardless of source given that there's CIM compliance.
 * Also included is a bonus props.conf for the Splunk_TA_symantec-ep app that adds the extra required fields for USB detection 
* Search that triggers every 4 hours if firewall data is missing
* Search that triggers if physical access has been denied more than 5 times for user last 24 hours

## Stand-alone searches (TO BE correlation searches)
* Potential password in user field: <pre>| tstats `summariesonly` values(Authentication.src) AS src,count from datamodel=Authentication.Authentication where Authentication.tag="failure" by Authentication.user  | `drop_dm_object_name("Authentication")` |  search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | `ut_shannon(user)` | where ut_shannon<4 AND ut_shannon>3  | sort count, - ut_shannon</pre>

## Threat lists
* Extra threat lists for ES
