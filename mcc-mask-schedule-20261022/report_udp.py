"""Offline acceptance/comparison; never modify baseline or start jobs."""
import csv,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from analyse_series import audit_job,udp_delta
from queue_stats import loss_deltas
from series_common import summarize,verify_queues
from selection_policy import validate as validate_policy
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def socket_check(result,final):
    rows={};assert set(final)==set(result['actors'])=={'6','7','8','9','10'}
    for user,start in result['actors'].items():
        buffer=start['udp_receive_buffer'];end=final[user]
        assert buffer['pid']==start['pid'] and buffer['effective_bytes']>=8388608 and buffer['effective_bytes']>buffer['before_bytes']
        assert not buffer['global_settings_changed'] and end['socket_owner_verified'] and end['actor_job']==result['attempt']['id']
        sockets=end['active_final_counters']['overlay_sockets']
        assert len(sockets)==1 and isinstance(sockets[0]['drops'],int) and sockets[0]['drops']>=0
        rows[user]={'effective_bytes':buffer['effective_bytes'],'before_bytes':buffer['before_bytes'],'method':buffer['method'],'drops':sockets[0]['drops'],'inode':sockets[0]['inode']}
    return {'passed':all(r['drops']==0 for r in rows.values()),'nodes':rows}
def comparison(baseline,summary):
    out={}
    for metric in ('native_successful','ssh_successful'):
        out[metric]={}
        for stat in ('median_s','p95_s'):
            a=baseline['summary'][metric][stat];b=summary[metric][stat]
            out[metric][stat]={'baseline_s':a,'new_s':b,'delta_s':None if b is None else b-a,'delta_percent':None if b is None or not a else 100*(b-a)/a}
    return out
def main():
    assert not (ROOT/'ACCEPTANCE.json').exists(),'Never overwrite a report'
    plan=read(ROOT/'SEALED-CONTRACT.json');host=read(ROOT/'HOST-STATUS.json');safe=read(ROOT/'FINAL-SAFETY-CHECK.json')
    basepath=ROOT.parent/'mcc_adaptive_series100_20261017/ACCEPTANCE.json'
    assert sha(basepath)==plan['baseline_acceptance_sha256']
    assert all(sha(Path(p))==h for p,h in plan['old_artifact_hashes'].items())
    planned={x['id']:x for x in plan['attempts']};results=[];audits=[];rounds=[];sockets=[]
    for folder in sorted((ROOT/'evidence').glob('round-*')):
        receipt=read(ROOT/(folder.name+'-RECEIVED.json'));assert sha(ROOT/(folder.name+'.tar.gz'))==receipt['sha256']
        before=read(folder/'UDP-BEFORE.json');after=read(folder/'UDP-AFTER.json')
        assert all(before[u]['rmem_sysctls']==after[u]['rmem_sysctls'] for u in before),'Global receive policy drift'
        queues=loss_deltas(read(folder/'ROUTER-BEFORE.json'),read(folder/'ROUTER-AFTER.json'));assert queues==read(folder/'LOSS-CHECK.json')
        rounds.append({'round':folder.name,'queue_drops':queues,'udp_errors':udp_delta(before,after)})
        for path in sorted(folder.glob('ike_privacy_*/RESULT.json')):
            r=read(path);assert r['attempt']==planned[r['attempt']['id']]
            assert all(validate_policy(actor['selection_policy']) for actor in r['actors'].values())
            results.append(r);audits.append(audit_job(path.parent,r));sockets.append({'id':r['attempt']['id'],**socket_check(r,read(path.parent/'ACTIVE-FINAL-COUNTERS.json'))})
    summary=summarize(results,20);ids={r['attempt']['id'] for r in results}
    assert ids==set(host.get('guest',{}).get('completed_ids',[])) and ids<=set(host.get('guest',{}).get('started_ids',[]))
    complete=host['stage']=='completed' and ids==set(planned);final=ROOT/'evidence/final';config_ok=False
    if final.exists():
        verify_queues(read(final/'ROUTER-READY.json'),read(ROOT/'EXPECTED-QUEUES.json'));verify_queues(read(final/'ROUTER-FINAL.json'),read(ROOT/'EXPECTED-QUEUES.json'))
        config_ok=bool(read(final/'NODE-SHUTDOWN.json')['passed'])
    captures_ok=bool(audits) and all(a['passed'] for a in audits);socket_ok=bool(sockets) and all(a['passed'] for a in sockets)
    counter_ok=bool(rounds) and all(a['queue_drops']['passed'] and a['udp_errors']['passed'] for a in rounds)
    safety=bool(safe.get('passed') and safe.get('copy_stopped') and safe.get('source_not_started'))
    passed=bool(complete and len(rounds)==1 and captures_ok and socket_ok and counter_ok and config_ok and safety and not summary['failed'])
    baseline=read(basepath);compare=comparison(baseline,summary)
    out={'stage':'verified' if passed else 'completed_with_findings' if complete else 'partial','passed':passed,'measurement_complete':complete,'summary':summary,'comparison':compare,
         'capture_delivery_passed':captures_ok,'per_socket_drop_gate_passed':socket_ok,'batch_counter_gate_passed':counter_ok,'rounds':rounds,'socket_audits':sockets,'capture_audits':audits,
         'queue_configuration_verified':config_ok,'copy_stopped':safety,'fragmented_messages':sum(a['messages'] for a in audits),'message_fragments':sum(a['fragments'] for a in audits),
         'pcaps_verified':sum(a['pcaps'] for a in audits),'old_files_preserved':len(plan['old_artifact_hashes']),'limitation':plan['comparability_limits'],
         'socket_counter_scope':'Fresh owned UDP9000 through final active snapshot; traffic after closure remains separately visible in captures/batch counters.',
         'selection_policy_verified_for_every_actor':True,'attack_cases_in_this_series':False}
    (ROOT/'ACCEPTANCE.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
    with (ROOT/'CONNECTIONS.csv').open('x',encoding='utf-8-sig',newline='') as stream:
        w=csv.writer(stream);w.writerow(('id','baseline_id','initiator','receiver','success','native_s','ssh_s','timeout'))
        for r in results:
            a=r['attempt'];w.writerow((a['id'],a['baseline_id'],a['initiator'],a['receiver'],r['success'],r['up']['elapsed_seconds'],r['ssh_elapsed_s'],r['up'].get('timeout',False)))
    n=summary['native_successful'];s=summary['ssh_successful'];base=baseline['summary']
    lines=['20 СОЕДИНЕНИЙ: КОМПАКТНЫЙ СОСЕДСКИЙ ФОРМАТ В ИЗОЛИРОВАННОЙ КОПИИ','',
        f"Завершено {summary['completed']}/20; успешно {summary['successful']}; отказов {summary['failed']}; тайм-аутов {summary['timeouts']}. Состояние: {out['stage']}.",
        f"На узле: медиана {n['median_s']} с; P95 {n['p95_s']} с. С SSH: медиана {s['median_s']} с; P95 {s['p95_s']} с.",
        f"Прошлая серия: на узле медиана {base['native_successful']['median_s']} с, P95 {base['native_successful']['p95_s']} с; с SSH медиана {base['ssh_successful']['median_s']} с, P95 {base['ssh_successful']['p95_s']} с.",
        f"Доставка фрагментов: {captures_ok}; сбросов собственного UDP9000 нет: {socket_ok}; общих UDP-ошибок/сбросов очередей нет: {counter_ok}.",
        f"Проверено сообщений {out['fragmented_messages']}, фрагментов {out['message_fragments']}, захватов {out['pcaps_verified']}.",
        'Запрос SO_RCVBUF: 4 МиБ; Linux возвращает удвоенный предел учётной памяти 8 МиБ. Если обычный запрос ограничен rmem_max, применяется штатная опция только этого сокета. Общие sysctl не меняются. Readback и drops каждого свежего сокета сохранены.',
        '20 направленных пар User6–User10, по одному соединению на пару, в порядке первого блока прежней серии. Fanout2×2×2 и seed0 сохранены. Это обычные соединения, не повторная серия атак.',
        'Выбор сохранён: adaptive, предел1с, минимум3 подлинные копии, пауза150мс. Компактный формат lv2/base64, кусок714, UDP<=1060; его версия и хеш проверяются у всех пяти акторов до IKE.',
        'Подписи и криптографические тела, UDP4MiB, очереди512 и max-limit0 не менялись. Соседский формат изменён. Используется прежняя сторонняя CHR7.24.5; ОС/EVE/strongSwan не обновлялись.',
        'Сравнение с прежними100 адаптивными соединениями историческое: разные загрузки и тестовые ключи, теперь только20 наблюдений. Это не парный случайный A/B и не проверка сокрытия получателя. Маскирующее расписание не установлено. P95 описывает эту малую выборку, не генеральную совокупность.',
        'Медиана/P95 успешных соединений приведены отдельно от отказов; все20 исходов сохраняются в CSV. P95 — линейная интерполяция позиции(n−1)×0,95. Подготовка акторов, ожидания и чтение очередей не включены в ipsec up.',
        'Навык fast-server-ops: изоляция, readback, сохранение оригиналов и штатное выключение. Исходный стенд, старые результаты/документы, Keenetic сохранены. Новых пакетов не установлено.',
        'Материалы: ACCEPTANCE.json, CONNECTIONS.csv, SEALED-CONTRACT.json, LOCAL-TESTS.json, FINAL-SAFETY-CHECK.json, evidence/round-01…05.']
    (ROOT/'REPORT-RU.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return {k:out[k] for k in ('stage','passed','measurement_complete','summary','capture_delivery_passed','per_socket_drop_gate_passed','batch_counter_gate_passed')}
if __name__=='__main__':print(json.dumps(main()))
