#!/usr/bin/env python3
"""
Heartbeat & Congestion Control Analyzer for RTCStats Dumps
Analyzes ICE consent keep-alives (RFC 7675) and available bandwidth
estimation from the nominated candidate-pair stats.
Outputs: <platform>_heartbeat_analysis/ folder with .txt, .json, .csv
"""

import json
import sys
import os
import csv
import io
from datetime import datetime

# CONFIGURATION
DEFAULT_FILEPATH = r"C:\Users\andri\OneDrive\Desktop\Master\Log Files\rtcstats_dump_zoom.json"

def make_output_folder(filepath):
    base_dir = os.path.dirname(os.path.abspath(filepath))
    platform = os.path.basename(filepath).replace('rtcstats_dump_', '').replace('.json', '')
    folder   = os.path.join(base_dir, f'{platform}_heartbeat_analysis')
    if not os.path.exists(folder):
        os.makedirs(folder)
    return folder, platform


def write_outputs(folder, platform, txt_content, data_dict, csv_rows):
    base = os.path.join(folder, f'{platform}_heartbeat')

    with open(base + '.txt', 'w', encoding='utf-8') as f:
        f.write(txt_content)

    with open(base + '.json', 'w', encoding='utf-8') as f:
        json.dump(data_dict, f, indent=2)

    fieldnames = [
        'snapshot', 'timestamp_ms', 'elapsed_s',
        'consent_requests_sent', 'consent_increment',
        'requests_sent', 'responses_received',
        'current_rtt_ms', 'avg_rtt_ms',
        'available_outgoing_kbps',
        'bytes_sent', 'bytes_received',
    ]
    with open(base + '.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"\n  Saved: {base}.txt")
    print(f"  Saved: {base}.json")
    print(f"  Saved: {base}.csv")

def analyze_heartbeat(filepath):

    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    with open(filepath, 'r') as f:
        lines = f.readlines()

    getstats = []
    for line in lines[2:]:
        try:
            event = json.loads(line.strip().rstrip(','))
            if isinstance(event, list) and event[0] == 'getStats':
                getstats.append(event[2])
        except:
            continue

    folder, platform = make_output_folder(filepath)

    buf = io.StringIO()
    def out(text=''):
        print(text)
        buf.write(str(text) + '\n')

    out("=" * 70)
    out("HEARTBEAT & CONGESTION CONTROL ANALYSIS")
    out("=" * 70)
    out(f"  Platform : {platform}")
    out(f"  File     : {filepath}")
    out(f"  Analyzed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Snapshots: {len(getstats)} getStats events")
    out()

    # Collect nominated candidate-pair timeline
    timeline = []

    for i, event in enumerate(getstats):
        for key, value in event.items():
            if not isinstance(value, dict): continue
            if value.get('type') != 'candidate-pair': continue
            if not value.get('nominated'): continue

            timeline.append({
                'snapshot':            i,
                'timestamp_ms':        value.get('timestamp', 0),
                'consent_sent':        value.get('consentRequestsSent', 0),
                'requests_sent':       value.get('requestsSent', 0),
                'responses_received':  value.get('responsesReceived', 0),
                'current_rtt':         value.get('currentRoundTripTime'),
                'total_rtt':           value.get('totalRoundTripTime'),
                'available_bw':        value.get('availableOutgoingBitrate'),
                'bytes_sent':          value.get('bytesSent', 0),
                'bytes_received':      value.get('bytesReceived', 0),
            })
            break  # one nominated pair per snapshot is enough

    if not timeline:
        out("  No nominated candidate-pair data found in this file.")
        out("  The call may not have fully connected or ICE was not captured.")
        return

    out(f"  Nominated pair snapshots: {len(timeline)}")
    out()

    # PART 1: ICE CONSENT KEEP-ALIVE (RFC 7675)
    out("=" * 70)
    out("1. ICE CONSENT KEEP-ALIVE  (RFC 7675)")
    out("=" * 70)
    out()
    out("  The browser sends periodic STUN Binding Requests to maintain")
    out("  consent to send media. These keep NAT mappings alive on the")
    out("  TURN relay and detect dead connections.")
    out()

    first = timeline[0]
    last  = timeline[-1]

    total_consent    = last['consent_sent'] - first['consent_sent']
    total_requests   = last['requests_sent'] - first['requests_sent']
    total_responses  = last['responses_received'] - first['responses_received']

    # Elapsed time from timestamps
    elapsed_ms = last['timestamp_ms'] - first['timestamp_ms']
    elapsed_s  = elapsed_ms / 1000.0

    out(f"  Capture duration          : {elapsed_s:.1f} seconds")
    out(f"  Total consent requests    : {last['consent_sent']} (cumulative)")
    out(f"  Requests during capture   : {total_consent}")
    out(f"  STUN requests sent        : {total_requests}")
    out(f"  STUN responses received   : {total_responses}")
    out()

    if elapsed_s > 0 and total_consent > 0:
        interval_s    = elapsed_s / total_consent
        rate_per_min  = (total_consent / elapsed_s) * 60

        out(f"  Estimated keep-alive interval : {interval_s:.1f} seconds")
        out(f"  Keep-alive rate               : {rate_per_min:.1f} requests/minute")
        out()

        if interval_s < 3:
            ka_assessment = "AGGRESSIVE (< 3s) - very fast dead-connection detection"
        elif interval_s <= 6:
            ka_assessment = "STANDARD (3-6s) - matches RFC 7675 recommended range"
        elif interval_s <= 15:
            ka_assessment = "RELAXED (6-15s) - slower than typical WebRTC"
        else:
            ka_assessment = "INFREQUENT (> 15s) - unusual for WebRTC"

        out(f"  Assessment : {ka_assessment}")
        out()

    # Response rate
    if total_requests > 0:
        response_rate = (total_responses / total_requests) * 100
        out(f"  STUN response rate : {response_rate:.1f}%")
        if response_rate == 100:
            out(f"  Finding: All keep-alives acknowledged — stable TURN connection throughout.")
        elif response_rate >= 95:
            out(f"  Finding: Minor packet loss on keep-alives ({100-response_rate:.1f}% unanswered).")
        else:
            out(f"  Finding: Significant keep-alive loss ({100-response_rate:.1f}%) — possible connectivity issues.")
    out()

    # Show increment pattern
    out("  Consent counter increments per snapshot (shows polling granularity):")
    increments = []
    for i in range(1, len(timeline)):
        diff = timeline[i]['consent_sent'] - timeline[i-1]['consent_sent']
        increments.append(diff)

    increment_counts = {}
    for inc in increments:
        increment_counts[inc] = increment_counts.get(inc, 0) + 1

    for val in sorted(increment_counts):
        bar    = '#' * min(increment_counts[val], 40)
        prefix = f'+{val}' if val >= 0 else str(val)
        out(f"    {prefix:4s} : {bar} ({increment_counts[val]} snapshots)")
    out()
    out("  Note: Increments > 1 mean multiple keep-alives fired between")
    out("  getStats polls — normal when polling interval > keep-alive interval.")
    out()

    # PART 2: CONGESTION CONTROL — AVAILABLE BANDWIDTH
    out("=" * 70)
    out("2. CONGESTION CONTROL — AVAILABLE OUTGOING BANDWIDTH")
    out("=" * 70)
    out()
    out("  availableOutgoingBitrate is the browser's real-time estimate of")
    out("  how much bandwidth is available for outgoing media. This is the")
    out("  primary output of WebRTC's GCC (Google Congestion Control) algorithm.")
    out()

    bw_samples = [t['available_bw'] for t in timeline if t['available_bw'] is not None]

    if bw_samples:
        bw_kbps    = [b / 1000 for b in bw_samples]
        avg_kbps   = sum(bw_kbps) / len(bw_kbps)
        min_kbps   = min(bw_kbps)
        max_kbps   = max(bw_kbps)
        first_kbps = bw_kbps[0]
        last_kbps  = bw_kbps[-1]

        out(f"  Samples collected : {len(bw_samples)}")
        out(f"  Starting estimate : {first_kbps:.0f} kbps")
        out(f"  Final estimate    : {last_kbps:.0f} kbps")
        out(f"  Average           : {avg_kbps:.0f} kbps")
        out(f"  Minimum           : {min_kbps:.0f} kbps")
        out(f"  Maximum           : {max_kbps:.0f} kbps")
        out(f"  Range             : {max_kbps - min_kbps:.0f} kbps")
        out()

        # Ramp-up detection — did it start low and climb?
        first_quarter = bw_kbps[:len(bw_kbps)//4] if len(bw_kbps) >= 4 else bw_kbps
        last_quarter  = bw_kbps[-(len(bw_kbps)//4):] if len(bw_kbps) >= 4 else bw_kbps
        avg_first = sum(first_quarter) / len(first_quarter)
        avg_last  = sum(last_quarter)  / len(last_quarter)

        if avg_last > avg_first * 1.5:
            out(f"  Ramp-up detected: avg first quarter {avg_first:.0f} kbps -> last quarter {avg_last:.0f} kbps")
            out(f"  Finding: Congestion controller ramped up bandwidth over the session.")
        elif avg_last < avg_first * 0.7:
            out(f"  Ramp-down detected: avg first quarter {avg_first:.0f} kbps -> last quarter {avg_last:.0f} kbps")
            out(f"  Finding: Congestion controller reduced estimate — possible network degradation.")
        else:
            out(f"  Finding: Bandwidth estimate stable throughout the session.")
        out()

        # Volatility
        if len(bw_kbps) > 1:
            changes = [abs(bw_kbps[i] - bw_kbps[i-1]) for i in range(1, len(bw_kbps))]
            avg_change = sum(changes) / len(changes)
            out(f"  Average change per snapshot : {avg_change:.0f} kbps")
            if avg_change < 50:
                out(f"  Stability: STABLE — estimate changes very little between polls")
            elif avg_change < 200:
                out(f"  Stability: MODERATE — some fluctuation in bandwidth estimate")
            else:
                out(f"  Stability: VOLATILE — large swings in bandwidth estimate")
        out()

        # Bandwidth timeline — simple ASCII view
        out("  Bandwidth estimate timeline (kbps, sampled every 5 snapshots):")
        step = max(1, len(bw_kbps) // 20)
        for i in range(0, len(bw_kbps), step):
            bar_len = int(bw_kbps[i] / max_kbps * 35) if max_kbps > 0 else 0
            bar = '|' * bar_len
            out(f"    t={i:3d}  {bw_kbps[i]:7.0f} kbps  {bar}")
        out()

    else:
        out("  availableOutgoingBitrate not found in candidate-pair stats.")
        out()

    # PART 3: RTT TIMELINE
    out("=" * 70)
    out("3. ROUND TRIP TIME TIMELINE (from candidate-pair)")
    out("=" * 70)
    out()
    out("  currentRoundTripTime on the candidate-pair is measured via STUN")
    out("  keep-alive responses — distinct from the audio RTT in remote-inbound-rtp.")
    out()

    rtt_samples = [(t['snapshot'], t['current_rtt']) for t in timeline if t['current_rtt'] is not None]

    if rtt_samples:
        rtt_ms = [r * 1000 for _, r in rtt_samples]
        avg_rtt = sum(rtt_ms) / len(rtt_ms)
        min_rtt = min(rtt_ms)
        max_rtt = max(rtt_ms)

        out(f"  Samples   : {len(rtt_ms)}")
        out(f"  Average   : {avg_rtt:.1f} ms")
        out(f"  Minimum   : {min_rtt:.1f} ms")
        out(f"  Maximum   : {max_rtt:.1f} ms")
        out(f"  Jitter    : {max_rtt - min_rtt:.1f} ms (range)")
        out()

        if avg_rtt < 50:
            out("  Assessment: EXCELLENT latency (< 50ms)")
        elif avg_rtt < 100:
            out("  Assessment: GOOD latency (50-100ms)")
        elif avg_rtt < 200:
            out("  Assessment: ACCEPTABLE latency (100-200ms)")
        else:
            out("  Assessment: HIGH latency (> 200ms)")
    out()

    # SUMMARY
    out("=" * 70)
    out("SUMMARY")
    out("=" * 70)
    out()
    out(f"  Platform                  : {platform}")
    out(f"  Capture duration          : {elapsed_s:.1f} seconds")
    if elapsed_s > 0 and total_consent > 0:
        out(f"  ICE keep-alive interval   : {elapsed_s/total_consent:.1f} seconds")
        out(f"  ICE keep-alive rate       : {(total_consent/elapsed_s)*60:.1f} per minute")
        out(f"  Keep-alive assessment     : {ka_assessment}")
    if total_requests > 0:
        out(f"  STUN response rate        : {(total_responses/total_requests)*100:.1f}%")
    if bw_samples:
        out(f"  Avg available bandwidth   : {avg_kbps:.0f} kbps")
        out(f"  Bandwidth range           : {min_kbps:.0f} - {max_kbps:.0f} kbps")
    if rtt_samples:
        out(f"  Avg RTT (STUN-based)      : {avg_rtt:.1f} ms")
    out()
    out("=" * 70)
    out("Analysis Complete!")
    out("=" * 70)

    # BUILD CSV ROWS & WRITE FILES
    first_ts = timeline[0]['timestamp_ms']
    csv_rows = []
    for i, t in enumerate(timeline):
        prev_consent = timeline[i-1]['consent_sent'] if i > 0 else t['consent_sent']
        rtt_ms_val   = round(t['current_rtt'] * 1000, 2) if t['current_rtt'] else None
        avg_rtt_val  = round((t['total_rtt'] / t['responses_received']) * 1000, 2) \
                       if t['total_rtt'] and t['responses_received'] else None
        csv_rows.append({
            'snapshot':                  t['snapshot'],
            'timestamp_ms':              t['timestamp_ms'],
            'elapsed_s':                 round((t['timestamp_ms'] - first_ts) / 1000, 2),
            'consent_requests_sent':     t['consent_sent'],
            'consent_increment':         t['consent_sent'] - prev_consent,
            'requests_sent':             t['requests_sent'],
            'responses_received':        t['responses_received'],
            'current_rtt_ms':            rtt_ms_val,
            'avg_rtt_ms':                avg_rtt_val,
            'available_outgoing_kbps':   round(t['available_bw'] / 1000) if t['available_bw'] else None,
            'bytes_sent':                t['bytes_sent'],
            'bytes_received':            t['bytes_received'],
        })

    data_dict = {
        'platform':              platform,
        'file':                  filepath,
        'analyzed_at':           datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'capture_duration_s':    round(elapsed_s, 1),
        'total_consent_requests': last['consent_sent'],
        'consent_during_capture': total_consent,
        'stun_requests_sent':    total_requests,
        'stun_responses_received': total_responses,
        'stun_response_rate_pct': round((total_responses/total_requests)*100, 1) if total_requests else None,
        'keepalive_interval_s':  round(elapsed_s/total_consent, 1) if total_consent else None,
        'keepalive_assessment':  ka_assessment if total_consent else 'N/A',
        'avg_available_kbps':    round(avg_kbps) if bw_samples else None,
        'min_available_kbps':    round(min_kbps) if bw_samples else None,
        'max_available_kbps':    round(max_kbps) if bw_samples else None,
        'avg_rtt_ms':            round(avg_rtt, 1) if rtt_samples else None,
        'min_rtt_ms':            round(min_rtt, 1) if rtt_samples else None,
        'max_rtt_ms':            round(max_rtt, 1) if rtt_samples else None,
        'timeline':              csv_rows,
    }

    print("\nOUTPUT FILES")
    print("-" * 70)
    write_outputs(folder, platform, buf.getvalue(), data_dict, csv_rows)


if __name__ == '__main__':
    filepath = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILEPATH
    analyze_heartbeat(filepath)