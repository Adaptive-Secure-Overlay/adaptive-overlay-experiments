"""Unchanged read-only RouterOS query contract; no configuration mutations."""
COMMANDS={
 'uptime':':put ("UPTIME|".[/system resource get uptime])',
 'interface':':foreach i in=[/interface print stats-detail as-value] do={:local n ($i->"name"); :if ([:pick $n 0 5]="ether") do={:put ("IF|".$n."|".[/interface get [find where name=$n] mac-address]."|".($i->"rx-packet")."|".($i->"tx-packet")."|".($i->"rx-drop")."|".($i->"tx-drop")."|".($i->"tx-queue-drop")."|".($i->"rx-error")."|".($i->"tx-error"))}}',
 'ethernet':':foreach i in=[/interface ethernet print stats as-value] do={:put ("ETH|".($i->"name")."|".($i->"rx-overflow")."|".($i->"rx-drop")."|".($i->"rx-error")."|".($i->"tx-drop"))}',
 'level':':do {:put ("LEVEL|".[/system license get level])} on-error={:put "LEVEL|unknown"}; :put ("VERSION|".[/system resource get version])',
 'queues':'/queue interface print detail without-paging',
 'types':'/queue type print detail without-paging',
 'simple':'/queue simple print stats without-paging',
 'tree':'/queue tree print stats without-paging',
 'raw_stats':'/interface print stats-detail without-paging',
 'tree_config':'/queue tree print detail without-paging',
 'simple_config':'/queue simple print detail without-paging'}
