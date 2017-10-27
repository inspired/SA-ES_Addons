# SA-ES_Addons
ES Add-ons

## Contents
### Correlation searches

#### Network - Custom - Unknown MAC address detected - Rule
Not yet created. See stand-alone search below

##### Use case
* Identify MAC addresses unknown to the organization, i.e. not belonging to the static list of MAC addresses

##### Actions
* Create notable event

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
* Identify passwords that are no longer secure. This is effectively a password sniffer. Use it sanely.

##### Actions
* Notify user/manager
* Disable user

## Stand-alone searches
(Now part of **Identity - Custom - Potential password in user name - Rule** correlation search )
* Potential password in user field: 
<code>| tstats `summariesonly` earliest(_time) AS starttime, latest(_time) AS endtime, latest(sourcetype) AS sourcetype, values(Authentication.src) AS src, values(Authentication.dest) AS dest, count from datamodel=Authentication.Authentication where Authentication.tag="failure" by Authentication.user  | `drop_dm_object_name("Authentication")` | search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | `ut_shannon(user)` | where ut_shannon<4 AND ut_shannon>3 AND mvcount(src) == 1  | sort count, - ut_shannon | eval incorrect_password=user | eval endtime=endtime+1000 | map maxsearches=70 search="| tstats `summariesonly` earliest(_time) AS starttime, latest(_time) AS endtime, latest(sourcetype) AS sourcetype, values(Authentication.src) AS src, values(Authentication.dest) AS dest,  count from datamodel=Authentication.Authentication where Authentication.tag=success Authentication.src=\"$src$\" Authentication.dest=\"$dest$\" sourcetype=\"$sourcetype$\" earliest=\"$starttime$\" latest=\"$endtime$\" by Authentication.user  | `drop_dm_object_name(\"Authentication\")` |  search RESTRICT_SEARCH_TERMS_FOR_ACCURACY | eval incorrect_password=\"$incorrect_password$\" | eval ut_shannon=\"$ut_shannon$\" | sort count" | where user!=incorrect_password | outlier action=RM count  | rex field=incorrect_password mode=sed "s/[aeiouAEIOU]/#/g"
</code>

* Unknown MAC address detected: <code>
index=switch source="/var/log/snmptrapd.log" 
| rex max_match=50000 field=_raw "(?msi)Hex-STRING:\s?(?<Hex_STRING>.+)\t"
| rex field=Hex_STRING mode=sed "s/\s\n/ /g"
| rex max_match=50000 field=Hex_STRING "(?<mac_status>([a-fA-F0-9][a-fA-F0-9]){1}) (?<mac_vlan>[a-fA-F0-9]{2} [a-fA-F0-9]{2}) (?<mac_addr>[a-fA-F0-9]{2} [a-fA-F0-9]{2} [a-fA-F0-9]{2} [a-fA-F0-9]{2} [a-fA-F0-9]{2} [a-fA-F0-9]{2}) (?<mac_portid>[a-fA-F0-9]{2} [a-fA-F0-9]{2})"
| rex field=mac_vlan mode=sed "s/ //g"
| rex field=mac_portid mode=sed "s/ //g"
| rex field=mac_addr mode=sed "s/ /:/g"
| eval mac_addr=lower(mac_addr)
| stats latest(_time) AS _time values(host) AS host latest(mac_status) AS mac_status latest(mac_vlan) AS vlan latest(mac_portid) AS mac_portid BY mac_addr
| eval vlan=tonumber(vlan,16)
| eval mac_portid=tonumber(mac_portid,16)
| eval mac_status=tonumber(mac_status,16)
| eval glue=mac_addr + ";" + vlan
| search NOT [|inputlookup IPDB-MAC.csv | eval mac_addr=lower(mac) | eval vlan='vlan number' | eval glue=mac_addr + ";" + vlan | fields glue]
| eval mac_status=case(mac_status == "0", "End of MIB object", mac_status == "1", "learnt", mac_status == "2", "removed")
| fields _time mac_addr host mac_status vlan mac_portid 
| rename mac_addr AS mac host AS "Reporting hosts" mac_status AS "Latest MAC Operation" mac_portid AS "Latest Port ID" 
| lookup mac_vendor_lookup mac OUTPUT mac_vendor, mac_vendor_address, mac_vendor_address2, mac_vendor_country
</code>

## Threat lists
* Extra threat lists for ES
