# _pe_
import argparse as arg, csv, hashlib as has2, json, statistics as sta5
from pathlib import Path

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def sta6(vals):
    vals = [v for v in vals if v is not None]
    return {'min': min(vals), 'max': max(vals), 'mean': sta5.mean(vals)} if vals else None

def sum2(dir2):
    res4 = read(dir2 / 'result.json')
    plan = read(dir2 / 'plan.json')
    rows = [json.loads(line) for line in (dir2 / 'telemetry.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    wrs = sorted([w for p in dir2.glob('api-writes-*.json') for w in read(p)['writes']], key=lambda w: w['monotonic'])
    post = read(dir2 / 'independent-postcheck.json') if (dir2 / 'independent-postcheck.json').exists() else None
    eve2 = read(dir2 / 'display-driver-events.json') if (dir2 / 'display-driver-events.json').exists() else None
    cle = read(dir2 / 'process-exit-check.json') if (dir2 / 'process-exit-check.json').exists() else None
    sta = []
    for mode in ('geometry', 'texture', 'fragment'):
        smp2 = [r for r in rows if r['phase'] == mode and r['elapsed_seconds'] >= 0]
        wor = res4['renderers'][mode]
        sta.append({'mode': mode, 'renderer': wor, 'samples': len(smp2), 'temperature_c': sta6([r['temperature_c'] for r in smp2]), 'gpu_utilization_percent': sta6([r['gpu_utilization_percent'] for r in smp2]), 'core_clock_mhz': sta6([r['core_clock_mhz'] for r in smp2]), 'memory_clock_mhz': sta6([r['memory_clock_mhz'] for r in smp2])})
    tem2 = [r['temperature_c'] for r in rows] + [r['temperature_c'] for r in res4['independent_restore']['temperature_samples']]
    ver4 = bool(res4['success'] and post and post['all_pstate_controls_match_baseline'] and post['fingerprints_unchanged'] and cle and cle['all_owned_processes_exited'])
    sum3 = {'verified_success': ver4, 'trial_directory': dir2.name, 'identity': plan['identity'], 'scheduled_render_seconds': 300, 'resolution': [1280, 720], 'fps_cap': 60, 'temperature_stop_c': plan['temperature_stop_c'], 'temperature_c': sta6(tem2), 'gpu_utilization_percent': sta6([r['gpu_utilization_percent'] for r in rows]), 'telemetry_samples': len(rows), 'stages': sta, 'api_writes': wrs, 'write_return_interval_seconds': wrs[-1]['monotonic'] - wrs[0]['monotonic'] if len(wrs) > 1 else None, 'parent_restore_verified': res4['parent_restore']['verified'], 'supervisor_restore_verified': res4['independent_restore']['restore']['verified'], 'postcheck': post, 'process_cleanup': cle, 'display_driver_events': eve2, 'configuration_and_code_hashes_unchanged': res4['source_fingerprints_unchanged'], 'memory_voltage_power_thermal_fan_setters_used': res4['memory_voltage_power_thermal_fan_setters_used'], 'scope': '720p/60 FPS capped OpenGL rendering with deterministic readback checks; not maximum-load or long-term stability certification'}
    (dir2 / 'summary.json').write_text(json.dumps(sum3, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    if rows:
        with (dir2 / 'telemetry.csv').open('w', encoding='utf-8-sig', newline='') as f:
            wri = csv.DictWriter(f, fieldnames=list(rows[0]))
            wri.writeheader()
            wri.writerows(rows)
    print(json.dumps({k: sum3[k] for k in ['verified_success', 'scheduled_render_seconds', 'temperature_c', 'gpu_utilization_percent', 'telemetry_samples', 'stages', 'write_return_interval_seconds', 'parent_restore_verified', 'supervisor_restore_verified', 'configuration_and_code_hashes_unchanged']}, indent=2, ensure_ascii=False))
    return sum3
if __name__ == '__main__':
    p = arg.ArgumentParser(description=__doc__)
    p.add_argument('--directory', type=Path, required=True)
    sum2(p.parse_args().directory.resolve())
