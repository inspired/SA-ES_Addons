# SA-Datametrix_ES_Addons
Datametrix ES Add-ons

## Contents
### Correlation searches
#### Endpoint - Custom - Unauthorized USB device blocked - Rule
Correlation search that creates a notable event for blocked USB devices connected to endpoints. Tested with the Symantec Endpoint Protection app but should work regardless of source given that there's CIM compliance.
* Also included is a bonus props.conf for the Splunk_TA_symantec-ep app that adds the extra required fields for USB detection.

#### Network - Custom - Data missing from Firewall - Rule
Search that triggers every 4 hours if firewall data is missing

#### Access - Custom - Physical access failure on multiple entry points - Rule
Search that triggers if physical access has been denied more than 5 times for user last 24 hours

#### Identity - Custom - Potential password in user name - Rule
Search that checks Shannon Entropy of username field to check if a password has been entered by mistake, and maps this to the next user that logged in from the same source to the same destination.

##### Use case
* Identify passwords that are no longer secure.
##### Actions
* Notify user/manager
* Disable user

## Stand-alone searches (TO BE correlation searches)
* Potential password in user field: <code>| tstats `summariesonly` values(Authentication.src) AS src,count from datamodel=Authentication.Authentication where Authentication.tag="failure" by Authentication.user  | `drop_dm_object_name("Authentication")` | search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | `ut_shannon(user)` | where ut_shannon<4 AND ut_shannon>3  | sort count, - ut_shannon</code>
 * Take2 (same but looks up closest actual user based on src and dest + time): <code>| tstats `summariesonly` earliest(_time) AS starttime, latest(_time) AS endtime, latest(sourcetype) AS sourcetype, values(Authentication.src) AS src, values(Authentication.dest) AS dest, count from datamodel=Authentication.Authentication where Authentication.tag="failure" by Authentication.user  | `drop_dm_object_name("Authentication")` | search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | `ut_shannon(user)` | where ut_shannon<4 AND ut_shannon>3  | sort count, - ut_shannon | eval incorrect_password=user | eval endtime=endtime+1000 | map maxsearches=70 search="| tstats `summariesonly` earliest(_time) AS starttime, latest(_time) AS endtime, latest(sourcetype) AS sourcetype, values(Authentication.src) AS src, values(Authentication.dest) AS dest, count from datamodel=Authentication.Authentication where Authentication.tag=success Authentication.src=\"$src$\" Authentication.dest=\"$dest$\" sourcetype=\"$sourcetype$\" earliest=\"$starttime$\" latest=\"$endtime$\" by Authentication.user  | `drop_dm_object_name(\"Authentication\")` | search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | eval incorrect_password=\"$incorrect_password$\" | eval ut_shannon=\"$ut_shannon$\" | sort count" | where user!=incorrect_password
</code>
* Take3: <code>| tstats `summariesonly` earliest(_time) AS starttime, latest(_time) AS endtime, latest(sourcetype) AS sourcetype, values(Authentication.src) AS src, values(Authentication.dest) AS dest, count from datamodel=Authentication.Authentication where Authentication.tag="failure" by Authentication.user  | `drop_dm_object_name("Authentication")` | search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | `ut_shannon(user)` | where ut_shannon<4 AND ut_shannon>3 AND mvcount(src) == 1  | sort count, - ut_shannon | eval incorrect_password=user | eval endtime=endtime+1000 | map maxsearches=70 search="| tstats `summariesonly` earliest(_time) AS starttime, latest(_time) AS endtime, latest(sourcetype) AS sourcetype, values(Authentication.src) AS src, values(Authentication.dest) AS dest,  count from datamodel=Authentication.Authentication where Authentication.tag=success Authentication.src=\"$src$\" Authentication.dest=\"$dest$\" sourcetype=\"$sourcetype$\" earliest=\"$starttime$\" latest=\"$endtime$\" by Authentication.user  | `drop_dm_object_name(\"Authentication\")` |  search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | eval incorrect_password=\"$incorrect_password$\" | eval ut_shannon=\"$ut_shannon$\" | sort count" | where user!=incorrect_password | outlier action=RM count  | rex field=incorrect_password mode=sed "s/[aeiouAEIOU]/#/g"
</code>

## Threat lists
* Extra threat lists for ES
