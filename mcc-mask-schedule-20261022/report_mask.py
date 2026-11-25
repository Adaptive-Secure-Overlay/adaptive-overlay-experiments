"""Offline observer-A evaluation after shutdown; no fitted ML or live connections."""
import importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from analyse_series import audit_job,udp_delta
from report_udp import socket_check
from mask_audit import ledger_check,capture_check
from series_common import describe,summarize,verify_queues
from queue_stats import loss_deltas
BASE=ROOT.parent/'mcc_compact_series20_20261019'
def read(p):return json.loads(p.read_text(encoding='utf-8'))

def features():
    path=ROOT.parent/'receiver_current_setup_observer_a_20261018/features.py'
    spec=importlib.util.spec_from_file_location('masked_observer_features',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def guesses(f,rows,source):
    tuples=[tuple(p[k] for k in ('time','src','dst','sport','dport','size')) for p in rows]
    return f.predict(tuples,int(source[4:]))[0]

def evaluate(samples,rules):
    return {r:{'correct':sum(s['predictions'][r]==s['label'] for s in samples),'total':len(samples),
               'accuracy':sum(s['predictions'][r]==s['label'] for s in samples)/len(samples) if samples else None} for r in rules}

def main():
    assert not (ROOT/'ACCEPTANCE.json').exists(),'Never replace retained acceptance'
    plan=read(ROOT/'SEALED-CONTRACT.json');host=read(ROOT/'HOST-STATUS.json');safe=read(ROOT/'FINAL-SAFETY-CHECK.json')
    f=features();planned={a['id']:a for a in plan['attempts']};results=[];audits=[];rounds=[]
    samples=[];prefix=[];baseline=[]
    for folder in sorted((ROOT/'evidence').glob('round-*')):
        before=read(folder/'UDP-BEFORE.json');after=read(folder/'UDP-AFTER.json')
        assert all(before[u]['rmem_sysctls']==after[u]['rmem_sysctls'] for u in before),'Global receive settings drift'
        rounds.append({'batch':folder.name,'udp':udp_delta(before,after),
                       'queues':loss_deltas(read(folder/'ROUTER-BEFORE.json'),read(folder/'ROUTER-AFTER.json'))})
        for p in sorted(folder.glob('ike_privacy_*/RESULT.json')):
            result=read(p);attempt=result['attempt'];assert attempt==planned[attempt['id']]
            results.append(result);final=read(p.parent/'ACTIVE-FINAL-COUNTERS.json')
            row={'id':attempt['id']}
            for name,fn in (('ledger',lambda:ledger_check(final,attempt['initiator'])),('socket',lambda:socket_check(result,final))):
                try:row[name]=fn()
                except Exception as error:row[name]={'passed':False,'coverage_unknown':True,'error_type':type(error).__name__}
            try:
                row['unwrapped_fragment_delivery']=audit_job(p.parent,result)
                capture=capture_check(p.parent,result,final)
                samples.append({'id':attempt['id'],'label':int(attempt['receiver'][4:]),'predictions':guesses(f,capture.pop('observer_rows'),attempt['initiator'])})
                prefix.append({'id':attempt['id'],'label':int(attempt['receiver'][4:]),'predictions':guesses(f,capture.pop('observer_prefix_rows'),attempt['initiator'])})
                row['capture']=capture
                old=next((BASE/'evidence').glob('round-*/'+attempt['baseline_id']+'/RESULT.json'))
                oldresult=read(old);assert (oldresult['attempt']['initiator'],oldresult['attempt']['receiver'])==(attempt['initiator'],attempt['receiver'])
                packets=f.decode(old.parent/(attempt['initiator']+'.pcap'));profile,views=f.windows(packets,int(attempt['initiator'][4:]));assert profile['valid']
                pred=f.predict(views['establishment_to_esp'],int(attempt['initiator'][4:]))[0]
                traffic_rows=[v for v in views['establishment_to_esp'] if 9000 in (v[3],v[4])]
                baseline.append({'id':attempt['baseline_id'],'label':int(attempt['receiver'][4:]),'predictions':pred,
                                 'packets':len(traffic_rows),'bytes':sum(v[5] for v in traffic_rows)})
            except Exception as error:row['audit_error']=type(error).__name__+': '+str(error)[:160]
            audits.append(row)
    summary=summarize(results,len(planned))
    usable=describe([r['up']['usable_elapsed_seconds'] for r in results if r['success']])
    ended=ROOT/'evidence/final';config=False
    if (ended/'ROUTER-FINAL.json').exists() and (ended/'ROUTER-READY.json').exists():
        verify_queues(read(ended/'ROUTER-READY.json'),read(ROOT/'EXPECTED-QUEUES.json'))
        verify_queues(read(ended/'ROUTER-FINAL.json'),read(ROOT/'EXPECTED-QUEUES.json'))
        config=bool(read(ended/'NODE-SHUTDOWN.json')['passed'])
    ids={r['attempt']['id'] for r in results}
    assert len(ids)==len(results) and ids==set(host.get('guest',{}).get('completed_ids',[]))
    complete=host['stage']=='completed' and ids==set(planned)
    delivery=bool(audits) and all(not a.get('audit_error') and a['ledger']['passed'] and a['socket']['passed'] and a.get('capture',{}).get('passed') and a.get('unwrapped_fragment_delivery',{}).get('passed') for a in audits)
    counters=bool(rounds) and all(v['udp']['passed'] and v['queues']['passed'] for v in rounds)
    capacity=read(ended/'CAPACITY-ACCEPTANCE.json') if (ended/'CAPACITY-ACCEPTANCE.json').exists() else {'passed':False,'coverage_unknown':True}
    memory_profile=read(ROOT/'MEMORY-RUNTIME-PROFILE.json') if (ROOT/'MEMORY-RUNTIME-PROFILE.json').exists() else {'passed':False}
    memory_grant=read(ROOT/'MEMORY-RUN-ADMISSION.json') if (ROOT/'MEMORY-RUN-ADMISSION.json').exists() else {'passed':False}
    memory_ok=memory_profile['passed'] and memory_grant['passed']
    passed=bool(complete and memory_ok and capacity['passed'] and delivery and counters and config and safe.get('passed') and safe.get('copy_stopped') and not summary['failed'])
    rules=list(f.rules.RULES)
    privacy={'primary_rule':'fewest_positive_packets','rules_fixed_before_new_captures':rules,'new':evaluate(samples,rules),
             'whole_saved_prefix_secondary':evaluate(prefix,rules),'matched_compact_baseline':evaluate(baseline,rules),
             'chance':.25,'samples':samples,'baseline_samples':baseline,
             'training':'none,18 fixed metadata rules; this is NOT a test of all ML attacks',
             'no_recipient_label_or_diagnostic_ledger_or_ESP_content_in_predictors':True,
             'limitations':'19 remaining directed pairs in one clone; prior failed pair is NOT rerun or counted successful. Descriptive only; not all ML attacks. Prefix includes preparation.'}
    traffic={'actual':{'packets_at_A':[a['capture']['packets_at_A'] for a in audits if 'capture' in a],
                       'ip_bytes_at_A':[a['capture']['ip_bytes_at_A'] for a in audits if 'capture' in a]},
             'matched_baseline':{'packets_at_A':[a['packets'] for a in baseline],'ip_bytes_at_A':[a['bytes'] for a in baseline]},
             'measurement':'Both directions at A, UDP9000, actual IP total bytes, strictly before firstESP; padding included. Not just useful bytes.'}
    out={'stage':'verified' if passed else 'completed_with_findings' if complete else 'partial','passed':passed,
         'measurement_complete':complete,'summary':summary,'usable_after_cover':usable,'capture_delivery_passed':delivery,
         'counter_gate_passed':counters,'queue_configuration_verified':config,'capacity_admission':capacity,'copy_stopped':safe.get('copy_stopped',False),
         'memory_admission':{'passed':memory_ok,'full_load_grant':memory_grant,'runtime_profile':'MEMORY-RUNTIME-PROFILE.json'},
         'privacy':privacy,'traffic':traffic,'audits':audits,'rounds':rounds,
         'comparability_limits':plan['comparability_limits'],'new_connections_started_by_report':0}
    with (ROOT/'ACCEPTANCE.json').open('x',encoding='utf-8') as stream:json.dump(out,stream,ensure_ascii=False,indent=2)
    lines=['МАСКИРУЮЩЕЕ РАСПИСАНИЕ: ИСПЫТАНИЕ ТОЛЬКО В КОПИИ',
           f"Готово {summary['completed']}/19 оставшихся; успешно {summary['successful']}; отказов {summary['failed']}. Приёмка: {out['stage']}. Предыдущая попытка6200 не повторена и не засчитана успехом новой версии.",
           f"Память: поэтапный допуск {memory_ok}. Старт только подготовки:48ГиБ RAM/36ГиБ commit; до IKE30с подтверждённого остатка≥16ГиБ при всех узлах, затем проверка каждую секунду. Подробности MEMORY-ADMISSION-RU.txt и MEMORY-RUNTIME-PROFILE.json.",
           f"Свежая двусторонняя проверка скорости до IKE: {capacity['passed']}. Действие: {capacity.get('repair')}. Измерительные UDP-пакеты отдельно в evidence/capacity-evidence/, в трафик20 соединений не включены.",
           f"Сама установка SA без SSH: {summary['native_successful']}. Готовность к передаче после расписания: {usable}. С SSH и ожиданием расписания: {summary['ssh_successful']}.",
           f"Доставка по захватам и внутренним журналам: {delivery}. Счётчики UDP/очередей: {counters}. Копия выключена: {out['copy_stopped']}.",
           f"Основное правило количества пакетов: {privacy['new']['fewest_positive_packets']}; на тех же парах до маскирования: {privacy['matched_compact_baseline']['fewest_positive_packets']}.",
           f"Реально передано у A: {traffic['actual']}; прежние пары: {traffic['matched_baseline']}.",
           'Фиксированные 1000 пакетов на участника в каждом направлении,1124 байта UDP/1152 байта IPv4. Окно2с+запас100мс. Честно включает пустышки и ожидание общего конца.',
           'Внутреннее ожидание подлинных копий1с и проверка подписей/повторов не сокращены. Исходный компактный код и буферы сохранены побайтно.',
           'Временная блокировка ESP в этом управляемом пилоте не является очередью данных: любой отброшенный ранний ESP делает приёмку неуспешной. Прикладной трафик разрешён только после общего окна. Это не готовый производственный механизм для произвольного приложения.',
           '18 правил выбраны заранее, без обучения.19 наблюдений недостаточно для вывода о стойкости ко всем ML-моделям. Адреса/содержимое ESP и внутренние хеши доставки не подавались предсказателям.',
           'Подробности: ACCEPTANCE.json, SEALED-CONTRACT.json, LOCAL-TESTS.json, FINAL-SAFETY-CHECK.json и evidence/. Старые результаты и документы не менялись.']
    with (ROOT/'REPORT-RU.txt').open('x',encoding='utf-8') as stream:stream.write('\n'.join(lines)+'\n')
    return {'stage':out['stage'],'passed':passed,'measurement_complete':complete,'summary':summary}
if __name__=='__main__':print(json.dumps(main()))
