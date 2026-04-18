def merge_dual_results(win10: dict, win11: dict) -> dict:
    """
    Laczy wyniki Win10 i Win11:
    - Deduplikuje IOC sieciowe (po value)
    - Liczy max behavior_score
    - Oznacza IOC specyficzne dla danego OS (only_win10 / only_win11)
    - Sumuje unikalne procesy, pliki, klucze rejestru
    """
    if not win10 and not win11:
        return {'max_score': 0, 'network_iocs': [], 'processes': [],
                'files_dropped': [], 'registry': [], 'os_diff': {}}

    w10 = win10 or {}; w11 = win11 or {}

    # Behavior score
    max_score = max(w10.get('behavior_score', 0), w11.get('behavior_score', 0))

    # Siec — deduplikacja + oznaczenie OS
    ioc_map = {}
    for ioc in w10.get('network_iocs', []):
        key = ioc.get('value','')
        ioc_map[key] = {**ioc, 'seen_on': ['win10']}
    for ioc in w11.get('network_iocs', []):
        key = ioc.get('value','')
        if key in ioc_map:
            ioc_map[key]['seen_on'].append('win11')
        else:
            ioc_map[key] = {**ioc, 'seen_on': ['win11']}

    network_iocs = list(ioc_map.values())

    # Procesy — unia
    procs10 = set(p.get('name','') for p in w10.get('processes', []))
    procs11 = set(p.get('name','') for p in w11.get('processes', []))
    processes = [
        {'name': n, 'seen_on': _seen(n, procs10, procs11)}
        for n in procs10 | procs11
    ]

    # Pliki — unia
    files10 = set(f.get('path','') for f in w10.get('files_dropped', []))
    files11 = set(f.get('path','') for f in w11.get('files_dropped', []))
    files_dropped = [
        {'path': p, 'seen_on': _seen(p, files10, files11)}
        for p in files10 | files11
    ]

    # Rejestr — unia
    reg10 = set(r.get('key','') for r in w10.get('registry', []))
    reg11 = set(r.get('key','') for r in w11.get('registry', []))
    registry = [
        {'key': k, 'seen_on': _seen(k, reg10, reg11)}
        for k in reg10 | reg11
    ]

    # Roznice OS (co widac tylko na jednym)
    os_diff = {
        'only_win10': {
            'network':  [i for i in network_iocs if i['seen_on'] == ['win10']],
            'processes':[p for p in processes    if p['seen_on'] == ['win10']],
        },
        'only_win11': {
            'network':  [i for i in network_iocs if i['seen_on'] == ['win11']],
            'processes':[p for p in processes    if p['seen_on'] == ['win11']],
        },
        'both': [i for i in network_iocs if len(i['seen_on']) == 2],
    }

    return dict(max_score=max_score, network_iocs=network_iocs,
                processes=processes, files_dropped=files_dropped,
                registry=registry, os_diff=os_diff)

def _seen(val, set10, set11):
    r = []
    if val in set10: r.append('win10')
    if val in set11: r.append('win11')
    return r
