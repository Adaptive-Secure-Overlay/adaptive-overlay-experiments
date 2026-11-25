"""Offline report invoked only after the finite controller stops its clone."""
import collections,csv,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import legacy_capture_decode as decoder
from queue_stats import loss_deltas
from series_common import summarize,verify_queues
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def udp_delta(before,after):
    assert set(before)==set(after)
    result={}
    for user,b in before.items():
        a=after[user];row={}
        for field in ('InErrors','RcvbufErrors','SndbufErrors','InCsumErrors'):
            x,y=b['udp'].get(field),a['udp'].get(field)
            assert isinstance(x,int) and isinstance(y,int) and y>=x,'Unknown or reset UDP counter'
            row[field]=y-x
        result[user]=row
    return {'passed':all(x==0 for row in result.values() for x in row.values()),'nodes':result}
def audit_job(work,r):
    assert not r['replayed'] and r['protocol_modified'] and r['compact_wire_version']==2 and r['queue_changes']==0
    assert all(a.get('compact_wire')=={'LINK_CIPHER_VERSION':2,'LINK_FRAG_MAX_WIRE':1060,'LINK_FRAG_CHUNK_BYTES':714} for a in r['actors'].values())
    manifest=read(work/'path-capture.json');assert manifest==r['capture_manifest'] and len(manifest['captures'])==5
    for cap in manifest['captures']:
        user=str(cap['node_id']//2);proof=r['captures'][user]
        assert proof['pcap']==cap['pcap'] and sha(work/cap['pcap'])==proof['sha256'] and proof['kernel_drops']==0
    groups,quality=decoder.decode(work/'path-capture.json');assert not quality['invalid_real_udp']
    endpoints={f"User{c['node_id']//2}":c['ifindex'] for c in manifest['captures']}
    missing=[];incomplete_source=[]
    for g in groups.values():
        sent=g['points'].get((endpoints[g['sender']],0));received=g['points'].get((endpoints[g['receiver']],4))
        full=set(range(g['total']))
        if not sent or sent['seq']!=full:
            incomplete_source.append({'sender':g['sender'],'receiver':g['receiver'],'frag_id':g['frag_id'],'total':g['total']})
        elif not received or received['seq']!=full:
            missing.append({'sender':g['sender'],'receiver':g['receiver'],'frag_id':g['frag_id'],
                            'missing':sorted(full-(received['seq'] if received else set()))})
    return {'id':r['attempt']['id'],'messages':len(groups),'fragments':sum(g['total'] for g in groups.values()),
            'missing':missing,'incomplete_source':incomplete_source,'quality':quality,'pcaps':5,
            'passed':not missing and not incomplete_source and bool(groups)}
def main():
    assert not (ROOT/'ACCEPTANCE.json').exists(), 'Saved report exists; do not overwrite'
    host=read(ROOT/'HOST-STATUS.json');plan=read(ROOT/'SEALED-CONTRACT.json')
    safe=read(ROOT/'FINAL-SAFETY-CHECK.json');assert safe['passed'] and safe['source_not_started'] and safe['copy_stopped']
    assert all(sha(Path(n))==v for n,v in plan['old_artifact_hashes'].items())
    results=[];audits=[];rounds=[]
    planned={x['id']:x for x in plan['attempts']}
    for folder in sorted((ROOT/'evidence').glob('round-*')):
        receipt=read(ROOT/(folder.name+'-RECEIVED.json'));assert sha(ROOT/(folder.name+'.tar.gz'))==receipt['sha256']
        before=read(folder/'ROUTER-BEFORE.json');after=read(folder/'ROUTER-AFTER.json');drops=loss_deltas(before,after)
        assert drops==read(folder/'LOSS-CHECK.json')
        udp=udp_delta(read(folder/'UDP-BEFORE.json'),read(folder/'UDP-AFTER.json'))
        round_results=[]
        for path in sorted(folder.glob('ike_privacy_*/RESULT.json')):
            r=read(path);assert r['attempt']==planned[r['attempt']['id']]
            audit=audit_job(path.parent,r);audits.append(audit);results.append(r);round_results.append(r['attempt']['id'])
        rounds.append({'round':folder.name,'completed_ids':round_results,'queue_drops':drops,'udp_errors':udp})
    summary=summarize(results,len(planned));final=ROOT/'evidence/final'
    final_ok=False
    if final.exists():
        expected=read(ROOT/'EXPECTED-QUEUES.json')
        verify_queues(read(final/'ROUTER-INITIAL.json'),expected);verify_queues(read(final/'ROUTER-FINAL.json'),expected)
        assert read(final/'QUEUE-REBOOT-ACCEPTANCE.json')['passed'] and read(final/'QUEUE-FINAL-ACCEPTANCE.json')['passed']
        assert read(final/'NODE-SHUTDOWN.json')['passed'];final_ok=True
    ids={v['attempt']['id'] for v in results};started=set(host.get('guest',{}).get('started_ids',[]));finished=set(host.get('guest',{}).get('completed_ids',[]))
    assert ids==finished and ids<=started
    complete=host['stage']=='completed' and final_ok and ids==set(planned) and all(v['completed']==5 for v in summary['pairs'].values())
    loss_ok=all(v['passed'] for v in audits) and all(v['queue_drops']['passed'] and v['udp_errors']['passed'] for v in rounds)
    accepted={'stage':'verified' if complete and loss_ok and summary['failed']==0 else 'measured_with_findings' if complete else 'partial',
              'passed':complete and loss_ok and summary['failed']==0,'measurement_complete':complete,'buffer_loss_gate_passed':loss_ok,
              'summary':summary,'rounds':rounds,'capture_audits':audits,'fragmented_messages':sum(v['messages'] for v in audits),
              'message_fragments':sum(v['fragments'] for v in audits),'pcaps_verified':sum(v['pcaps'] for v in audits),
              'old_files_preserved':len(plan['old_artifact_hashes']),'source_and_old_results_preserved':True,
              'copy_stopped':True,'queue_changes':0,'connections_replayed':0,'unreported_started_ids':sorted(started-ids),
              'limitation':'Endpoint delivery and batch-level router/UDP drop counters; not per-hop loss localization. Repeated pairs share this stand and are not independent traffic populations.'}
    (ROOT/'ACCEPTANCE.json').write_text(json.dumps(accepted,ensure_ascii=False,indent=2),encoding='utf-8')
    with (ROOT/'CONNECTIONS.csv').open('w',encoding='utf-8-sig',newline='') as stream:
        writer=csv.writer(stream);writer.writerow(('id','batch','initiator','receiver','success','native_s','ssh_s','timeout','direct_ike','esp'))
        for r in results:
            a=r['attempt'];writer.writerow((a['id'],a['batch'],a['initiator'],a['receiver'],r['success'],r['up']['elapsed_seconds'],r['ssh_elapsed_s'],r['up'].get('timeout',False),r['packet_counts']['direct_ike'],r['packet_counts']['esp']))
    n=summary['native_successful'];s=summary['ssh_successful']
    lines=['ПРОВЕРКА БУФЕРОВ НА 100 СОЕДИНЕНИЯХ USER6–USER10','',
           f"Состояние: {accepted['stage']}. Завершено {summary['completed']}/100; успешных {summary['successful']}; неуспешных {summary['failed']}; тайм-аутов {summary['timeouts']}. Повторов уже начатых попыток нет.",
           'Пять блоков по 20 направленных пар; каждая пара проверяется пять раз, порядок перемешан заранее. Очереди только читались: PFIFO512 и max-limit=0 должны совпадать с сохранённым состоянием до выключения. Лицензии Free и остальные настройки не менялись. Ограничение 900 кбит/с не вводилось.', '',
           f"Успешные соединения, измерение на узле: медиана {n['median_s']} с; эмпирический P95 {n['p95_s']} с; диапазон {n['min_s']}–{n['max_s']} с.",
           f"Успешные соединения, измерение с SSH: медиана {s['median_s']} с; эмпирический P95 {s['p95_s']} с.",
           'Медиана и P95 вычислены отдельно для успешных соединений; отказы и тайм-ауты приведены выше и в CSV, а не исключены без следа. Предел ожидания — 90 с. P95 — описательная оценка этой серии, линейная интерполяция Python statistics.quantiles(method=inclusive); это не доверительная граница генеральной совокупности.', '',
           f"По захватам проверено {accepted['fragmented_messages']} фрагментированных сообщений, {accepted['message_fragments']} фрагментов и {accepted['pcaps_verified']} pcap-файлов. Проверка доставки, сбросов очередей и UDP-ошибок: {loss_ok}.",
           'Все пять конечных мостов захватывались в каждой попытке одинаково. Счётчики 14 маршрутизаторов и UDP конечных узлов сняты до/после каждого блока. Внутри блока отдельной попытке прирост общего счётчика не приписывается. Это контроль доставки и сбросов, не повторная локализация потерь по каждому транзитному порту.', '',
           'Результаты по парам (по пяти попыткам P95 не квалифицируется):']
    for pair,values in summary['pairs'].items():lines.append(f"{pair}: {values['successful']}/{values['completed']} успешно; медиана на узле {values['native_successful']['median_s']} с.")
    lines.extend(['','Прежние три диагностических соединения и эта серия не объединяются: здесь одинаковые пять захватов конечных мостов, без 53 непрерывных транзитных захватов. Время подготовки узлов, перезапуска акторов, трёхсекундного ожидания и чтения очередей в измерение ipsec up не входит.',
                  f"Сохранность: проверены хеши {accepted['old_files_preserved']} старых файлов; исходный стенд не запускался, копия выключена. Протокольный код, ОС/EVE-NG/strongSwan, Keenetic, лицензии, старые результаты, диссертация и презентация не менялись. Навык fast-server-ops применён для изоляции, проверки очередей после включения и чистого завершения, а не для изменения внешней инфраструктуры.",
                  'Материалы: ACCEPTANCE.json, CONNECTIONS.csv, SEALED-CONTRACT.json, FINAL-SAFETY-CHECK.json, LOCAL-TESTS.json, evidence/round-01…05 и evidence/final. Незавершённую серию или потерю качества захвата полным успехом не считать.'])
    (ROOT/'REPORT-RU.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return {'passed':accepted['passed'],'stage':accepted['stage'],'completed':summary['completed'],'successful':summary['successful'],'native':n,'ssh':s}
if __name__=='__main__':print(json.dumps(main()))
