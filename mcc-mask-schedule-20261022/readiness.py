"""Fail-closed evidence gate before any of the 100 new IKE connections."""
import math
IDS={1,13,15,17,19,21,26,27,28,29,30,31,32,33}
ARCHIVE='1f2bd373a160a1aff1622be727a048b8acde7f9f1664f7909cb1e6457414e755'
def validate(v):
 assert v.get('passed') and v.get('queue_configuration_preserved') and v.get('external_nics_absent')
 assert v.get('candidate_code_archive_sha256')==ARCHIVE
 rows=v['routers'];assert {int(n) for n in rows}==IDS
 for row in rows.values():
  assert row['reported_license_level']=='p-unlimited' and row['version'].startswith('7.24.5')
  rate=row['measured_tx_bps'];assert isinstance(rate,(int,float)) and math.isfinite(rate) and rate>1_000_000
  assert row['measurement_duration_s']>=5 and row['egress_interface_verified'] and row['measured_egress_byte_delta']>0
 return {'passed':True,'routers':14,'minimum_measured_bps':min(r['measured_tx_bps'] for r in rows.values()),'not_a_claim_of_infinite_bandwidth':True}
