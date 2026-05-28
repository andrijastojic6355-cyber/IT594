#!/usr/bin/env python3
"""
Screen Share Analyzer for RTCStats Dumps
Detects screen sharing activity and extracts codec, quality,
bandwidth, PeerConnection lifecycle, and static-content optimization.
Outputs: <platform>_ss_analysis/ folder with .txt, .json, .csv files.
"""

import json
import sys
import os
import csv
import io
from datetime import datetime

# CONFIGURATION
DEFAULT_FILEPATH = r"C:\Users\andri\OneDrive\Desktop\Master\Log Files\rtcstats_dump_teams_ss_test2.json"

def make_output_folder(filepath):
    """Create (or reuse) <platform>_ss_analysis folder next to the input file."""
    base_dir = os.path.dirname(os.path.abspath(filepath))
    filename = os.path.basename(filepath)
    platform = filename.replace('rtcstats_dump_', '').replace('.json', '')
    folder   = os.path.join(base_dir, f'{platform}_ss_analysis')
    if not os.path.exists(folder):
        os.makedirs(folder)
    return folder, platform


def write_outputs(folder, platform, txt_content, data_dict, csv_rows):
    """Write .txt, .json, .csv into the output folder."""
    base = os.path.join(folder, f'{platform}_screenshare')

    with open(base + '.txt', 'w', encoding='utf-8') as f:
        f.write(txt_content)

    with open(base + '.json', 'w', encoding='utf-8') as f:
        json.dump(data_dict, f, indent=2)

    fieldnames = [
        'ssrc', 'role', 'codec', 'resolution', 'avg_fps',
        'total_mb', 'avg_kbps', 'peak_kbps',
        'nack_count', 'pli_count', 'quality_limitation',
        'static_intervals_pct'
    ]
    with open(base + '.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"\n  Saved: {base}.txt")
    print(f"  Saved: {base}.json")
    print(f"  Saved: {base}.csv")


def load_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()
    all_events = []
    getstats   = []
    for line in lines[2:]:
        try:
            event = json.loads(line.strip().rstrip(','))
            if isinstance(event, list) and len(event) > 0:
                all_events.append(event)
                if event[0] == 'getStats':
                    getstats.append(event[2])
        except:
            continue
    return all_events, getstats


def analyze_screenshare(filepath):

    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    all_events, getstats = load_file(filepath)
    folder, platform     = make_output_folder(filepath)

    # Capture all print output into a string so we can write it to .txt too
    buf = io.StringIO()

    def out(text=''):
        print(text)
        buf.write(text + '\n')

    out("=" * 70)
    out("SCREEN SHARE ANALYSIS")
    out("=" * 70)
    out(f"  Platform : {platform}")
    out(f"  File     : {filepath}")
    out(f"  Analyzed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"  Events   : {len(getstats)} getStats snapshots")
    out()

    # PART 1: DETECTION
    out("=" * 70)
    out("1. SCREEN SHARE DETECTION")
    out("=" * 70)
    out()

    display_media_detected     = False
    display_media_constraints  = {}
    display_media_track_label  = None
    camera_requests            = []

    for e in all_events:
        etype = e[0]
        if etype == 'navigator.mediaDevices.getDisplayMedia':
            display_media_detected = True
            if len(e) > 2 and isinstance(e[2], dict):
                raw_video = e[2].get('video', '{}')
                try:
                    display_media_constraints = json.loads(raw_video) if isinstance(raw_video, str) else raw_video
                except:
                    display_media_constraints = {}
        if etype == 'navigator.mediaDevices.getDisplayMediaOnSuccess':
            if len(e) > 2 and isinstance(e[2], list):
                for track in e[2]:
                    if isinstance(track, list) and len(track) >= 3:
                        display_media_track_label = track[2]
        if etype == 'navigator.mediaDevices.getUserMedia':
            if len(e) > 2 and isinstance(e[2], dict) and 'video' in e[2]:
                camera_requests.append(e[2].get('video'))

    if display_media_detected:
        out(f"  Screen Share Detected  : YES")
        out(f"  Detection Method       : navigator.mediaDevices.getDisplayMedia event")
        if display_media_track_label:
            out(f"  Track Label            : {display_media_track_label}  (confirms screen capture, not camera)")
        if display_media_constraints:
            max_w      = display_media_constraints.get('width',     {}).get('max', 'N/A')
            max_h      = display_media_constraints.get('height',    {}).get('max', 'N/A')
            ideal_fps  = display_media_constraints.get('frameRate', {}).get('ideal', 'N/A')
            out(f"  Requested Resolution   : up to {max_w}x{max_h}")
            out(f"  Requested Frame Rate   : {ideal_fps} fps (ideal)")
        out()

        content_type_confirmed = False
        for event in getstats:
            for key, value in event.items():
                if isinstance(value, dict) and value.get('contentType') == 'screenshare':
                    content_type_confirmed = True
                    break
            if content_type_confirmed:
                break

        out(f"  Confirmed in Stats     : {'YES - contentType=screenshare found in outbound-rtp' if content_type_confirmed else 'contentType field not present'}")
    else:
        out(f"  Screen Share Detected  : NO")
        out(f"  This capture contains camera/audio only.")
        out()
        # Still write the txt so the user knows what happened
        folder, platform = make_output_folder(filepath)
        write_outputs(folder, platform, buf.getvalue(),
                      {'screen_share_detected': False},
                      [])
        return

    camera_active = bool(camera_requests)
    out(f"  Camera also active     : {'YES' if camera_active else 'NO (screen-only session)'}")
    out()

    # PART 2: PEERCONNECTION LIFECYCLE
    out("=" * 70)
    out("2. PEERCONNECTION LIFECYCLE")
    out("=" * 70)
    out()

    pc_events         = []
    negotiation_count = 0
    for e in all_events:
        if e[0] in ('create', 'close', 'remove'):
            pc_id = e[1] if len(e) > 1 else 'N/A'
            ts    = e[-1] if len(e) > 1 else 'N/A'
            pc_events.append((e[0], pc_id, ts))
        if e[0] in ('createOffer', 'setLocalDescription', 'setRemoteDescription'):
            negotiation_count += 1

    pc_ids     = set(p[1] for p in pc_events if p[1] not in (None, 'N/A'))
    pc_created = sum(1 for p in pc_events if p[0] == 'create' and p[1] not in (None, 'N/A'))
    renegotiations = negotiation_count // 3

    out(f"  PeerConnections created : {pc_created}")
    out(f"  PC IDs seen             : {sorted(pc_ids)}")
    out(f"  Renegotiations          : {renegotiations} (createOffer + setLocal + setRemote cycles)")
    out()
    out("  Timeline:")
    for action, pc_id, ts in pc_events:
        if pc_id not in (None, 'N/A'):
            ts_str = f"{ts:.1f} ms" if isinstance(ts, float) else str(ts)
            out(f"    {action:8s}  PC={pc_id}  (relative ts: {ts_str})")
    out()

    note_separate_pc = len(pc_ids) > 1
    if note_separate_pc:
        out(f"  Finding: Platform opened a SEPARATE PeerConnection for screen share.")
        out(f"           Full new DTLS handshake for the screen share stream.")
    else:
        out(f"  Finding: Screen share added to the EXISTING PeerConnection (same DTLS).")
    out()

    # PART 3: CODEC IDENTIFICATION
    out("=" * 70)
    out("3. CODEC IDENTIFICATION")
    out("=" * 70)
    out()

    codec_lookup = {}
    for event in getstats:
        for key, value in event.items():
            if isinstance(value, dict) and value.get('type') == 'codec':
                codec_lookup[key] = {
                    'mimeType':    value.get('mimeType', ''),
                    'clockRate':   value.get('clockRate', ''),
                    'sdpFmtpLine': value.get('sdpFmtpLine', ''),
                }

    ss_ssrc_codecs  = {}
    cam_ssrc_codecs = {}

    for event in getstats:
        for key, value in event.items():
            if not isinstance(value, dict): continue
            if value.get('type') != 'outbound-rtp': continue
            ssrc         = value.get('ssrc')
            content_type = value.get('contentType', '')
            kind         = value.get('kind', '')
            codec_id     = value.get('codecId', '')
            if not ssrc or kind != 'video': continue
            if content_type == 'screenshare':
                ss_ssrc_codecs.setdefault(ssrc, set())
                if codec_id: ss_ssrc_codecs[ssrc].add(codec_id)
            else:
                cam_ssrc_codecs.setdefault(ssrc, set())
                if codec_id: cam_ssrc_codecs[ssrc].add(codec_id)

    def resolve_codecs(ssrc_map):
        mimes = set()
        for ssrc, cids in ssrc_map.items():
            for cid in cids:
                mime = codec_lookup.get(cid, {}).get('mimeType', '')
                if mime: mimes.add(mime)
        return mimes

    ss_codecs  = resolve_codecs(ss_ssrc_codecs)
    cam_codecs = resolve_codecs(cam_ssrc_codecs)
    codec_switch = bool(ss_codecs and cam_codecs and ss_codecs != cam_codecs)

    out(f"  Screen Share codec(s)  : {', '.join(ss_codecs) if ss_codecs else 'N/A'}")
    out(f"  Camera codec(s)        : {', '.join(cam_codecs) if cam_codecs else 'N/A'}")
    out()
    if codec_switch:
        out(f"  Finding: Platform uses DIFFERENT codecs for screen share vs camera.")
        out(f"           Screen share : {', '.join(ss_codecs)}")
        out(f"           Camera       : {', '.join(cam_codecs)}")
    elif ss_codecs and cam_codecs:
        out(f"  Finding: Platform uses the SAME codec for both screen share and camera.")
    out()

    seen_mimes = set()
    ss_codec_ids = set()
    for ids in ss_ssrc_codecs.values(): ss_codec_ids.update(ids)
    for cid in ss_codec_ids:
        info = codec_lookup.get(cid, {})
        mime = info.get('mimeType', '')
        if mime and mime not in seen_mimes:
            seen_mimes.add(mime)
            fmtp = info.get('sdpFmtpLine', 'none')
            out(f"  {mime}  clockRate={info.get('clockRate','')}  params={fmtp}")
    out()

    # PART 4: STREAM QUALITY & BANDWIDTH
    out("=" * 70)
    out("4. STREAM QUALITY & BANDWIDTH")
    out("=" * 70)
    out()

    ss_streams = {}
    for event in getstats:
        for key, value in event.items():
            if not isinstance(value, dict): continue
            if value.get('type') != 'outbound-rtp': continue
            if value.get('contentType') != 'screenshare': continue
            if value.get('kind') != 'video': continue
            ssrc = value.get('ssrc')
            if not ssrc: continue
            if ssrc not in ss_streams:
                ss_streams[ssrc] = {
                    'bytes_timeline': [], 'fps_samples': [],
                    'width_samples': [], 'height_samples': [],
                    'quality_limits': set(),
                    'nack_count': 0, 'pli_count': 0,
                }
            d = ss_streams[ssrc]
            d['bytes_timeline'].append(value.get('bytesSent', 0) or 0)
            if value.get('framesPerSecond'): d['fps_samples'].append(value['framesPerSecond'])
            if value.get('frameWidth'):      d['width_samples'].append(value['frameWidth'])
            if value.get('frameHeight'):     d['height_samples'].append(value['frameHeight'])
            if value.get('qualityLimitationReason'): d['quality_limits'].add(value['qualityLimitationReason'])
            d['nack_count'] = max(d['nack_count'], value.get('nackCount', 0) or 0)
            d['pli_count']  = max(d['pli_count'],  value.get('pliCount',  0) or 0)

    csv_rows     = []
    stream_data  = []   # for JSON

    if not ss_streams:
        out("  No screen share video streams found in getStats data.")
        out()
    else:
        sorted_streams = sorted(ss_streams.items(),
                                key=lambda x: x[1]['bytes_timeline'][-1] if x[1]['bytes_timeline'] else 0,
                                reverse=True)
        labels = ['PRIMARY', 'SECONDARY', 'TERTIARY']

        for idx, (ssrc, d) in enumerate(sorted_streams):
            label      = labels[idx] if idx < len(labels) else f'LAYER {idx+1}'
            total_mb   = (d['bytes_timeline'][-1] if d['bytes_timeline'] else 0) / (1024*1024)
            avg_fps    = sum(d['fps_samples']) / len(d['fps_samples']) if d['fps_samples'] else 0
            max_w      = max(d['width_samples'])  if d['width_samples']  else 0
            max_h      = max(d['height_samples']) if d['height_samples'] else 0
            res_str    = f"{max_w}x{max_h}" if max_w else "N/A"

            bitrates = []
            for i in range(1, len(d['bytes_timeline'])):
                delta = d['bytes_timeline'][i] - d['bytes_timeline'][i-1]
                if delta >= 0:
                    bitrates.append((delta * 8) / 1000)

            avg_kbps     = sum(bitrates) / len(bitrates) if bitrates else 0
            max_kbps     = max(bitrates) if bitrates else 0
            zero_int     = sum(1 for b in bitrates if b < 10)
            static_pct   = (zero_int / len(bitrates) * 100) if bitrates else 0
            ql_str       = ', '.join(d['quality_limits']) if d['quality_limits'] else 'none'
            ss_codec_str = ', '.join(ss_codecs) if ss_codecs else 'N/A'

            out(f"  [{label}]  SSRC: {ssrc}")
            out(f"    Resolution        : {res_str}")
            out(f"    Avg Frame Rate    : {avg_fps:.1f} fps")
            out(f"    Total Data Sent   : {total_mb:.2f} MB")
            out(f"    Avg Bitrate       : {avg_kbps:.0f} kbps")
            out(f"    Peak Bitrate      : {max_kbps:.0f} kbps")
            out(f"    NACK Count        : {d['nack_count']}")
            out(f"    PLI Count         : {d['pli_count']}")
            out(f"    Quality Limit     : {ql_str}")
            out(f"    Static Opt.       : {static_pct:.1f}% of intervals near-zero bitrate")
            out()

            csv_rows.append({
                'ssrc': ssrc, 'role': label, 'codec': ss_codec_str,
                'resolution': res_str, 'avg_fps': round(avg_fps, 1),
                'total_mb': round(total_mb, 2), 'avg_kbps': round(avg_kbps),
                'peak_kbps': round(max_kbps), 'nack_count': d['nack_count'],
                'pli_count': d['pli_count'], 'quality_limitation': ql_str,
                'static_intervals_pct': round(static_pct, 1),
            })
            stream_data.append({
                'ssrc': ssrc, 'role': label, 'codec': ss_codec_str,
                'resolution': res_str, 'avg_fps': round(avg_fps, 1),
                'total_mb': round(total_mb, 2), 'avg_kbps': round(avg_kbps),
                'peak_kbps': round(max_kbps), 'nack_count': d['nack_count'],
                'pli_count': d['pli_count'], 'quality_limitation': ql_str,
                'static_intervals_pct': round(static_pct, 1),
                'bytes_timeline': d['bytes_timeline'],
            })

        active_streams = sum(1 for _, d in sorted_streams
                             if (d['bytes_timeline'][-1] if d['bytes_timeline'] else 0) > 0)
        out(f"  Simulcast on screen share : {len(ss_streams)} SSRC(s) total, {active_streams} with data")
        out(f"  Finding: {'Multiple simulcast layers for screen share.' if len(ss_streams) > 1 else 'Single stream - no simulcast for screen share.'}")
        out()

    # PART 5: STATIC CONTENT OPTIMIZATION
    out("=" * 70)
    out("5. STATIC CONTENT OPTIMIZATION")
    out("=" * 70)
    out()
    out("  How well does the platform reduce bitrate on a static/unchanged screen?")
    out()

    static_rating = 'N/A'
    static_near_zero_pct = 0.0

    if ss_streams and sorted_streams:
        _, primary_data = sorted_streams[0]
        bitrates = []
        for i in range(1, len(primary_data['bytes_timeline'])):
            delta = primary_data['bytes_timeline'][i] - primary_data['bytes_timeline'][i-1]
            if delta >= 0:
                bitrates.append((delta * 8) / 1000)

        if bitrates:
            total       = len(bitrates)
            near_zero   = sum(1 for b in bitrates if b < 10)
            low_band    = sum(1 for b in bitrates if 10 <= b < 100)
            active_band = sum(1 for b in bitrates if b >= 100)
            static_near_zero_pct = near_zero / total * 100

            out(f"  Bitrate distribution (primary stream, {total} intervals):")
            out(f"    Near-zero  (<10 kbps)  : {near_zero:3d} intervals  ({near_zero/total*100:.1f}%)  <- static screen")
            out(f"    Low        (10-100 kbps): {low_band:3d} intervals  ({low_band/total*100:.1f}%)")
            out(f"    Active     (>100 kbps)  : {active_band:3d} intervals  ({active_band/total*100:.1f}%)  <- screen changing")
            out()

            if static_near_zero_pct > 30:
                static_rating = "GOOD - drops bitrate effectively on static content"
            elif static_near_zero_pct > 10:
                static_rating = "MODERATE - some optimization on static content"
            else:
                static_rating = "LIMITED - continuous bitrate even on static screens"

            out(f"  Static optimization rating: {static_rating}")
    out()

    # SUMMARY
    out("=" * 70)
    out("SUMMARY")
    out("=" * 70)
    out()
    out(f"  Platform              : {platform}")
    out(f"  Screen Share Present  : YES")
    if display_media_track_label:
        out(f"  Track Label           : {display_media_track_label}")
    out(f"  Separate PC opened    : {'YES' if note_separate_pc else 'NO'}")
    out(f"  Renegotiations        : {renegotiations}")
    out(f"  Screen Share Codec(s) : {', '.join(ss_codecs) if ss_codecs else 'N/A'}")
    out(f"  Camera Codec(s)       : {', '.join(cam_codecs) if cam_codecs else 'N/A'}")
    out(f"  Codec switch on SS    : {'YES' if codec_switch else 'NO'}")
    if ss_streams and sorted_streams:
        p_ssrc, p_data = sorted_streams[0]
        max_w  = max(p_data['width_samples'])  if p_data['width_samples']  else 0
        max_h  = max(p_data['height_samples']) if p_data['height_samples'] else 0
        avg_fp = sum(p_data['fps_samples'])/len(p_data['fps_samples']) if p_data['fps_samples'] else 0
        out(f"  SS Resolution         : {max_w}x{max_h}")
        out(f"  SS Avg Frame Rate     : {avg_fp:.1f} fps")
        out(f"  SS Simulcast Streams  : {len(ss_streams)}")
    out(f"  Static Optimization   : {static_rating}")
    out()
    out("=" * 70)
    out("Analysis Complete!")
    out("=" * 70)

    # WRITE OUTPUT FILES
    out()
    out("OUTPUT FILES")
    out("-" * 70)

    data_dict = {
        'platform':              platform,
        'file':                  filepath,
        'analyzed_at':           datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'screen_share_detected': display_media_detected,
        'track_label':           display_media_track_label,
        'separate_pc_opened':    note_separate_pc,
        'renegotiations':        renegotiations,
        'ss_codecs':             list(ss_codecs),
        'camera_codecs':         list(cam_codecs),
        'codec_switch':          codec_switch,
        'static_optimization':   static_rating,
        'static_near_zero_pct':  round(static_near_zero_pct, 1),
        'streams':               stream_data,
    }

    write_outputs(folder, platform, buf.getvalue(), data_dict, csv_rows)

# ENTRY POINT
if __name__ == '__main__':
    filepath = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILEPATH
    analyze_screenshare(filepath)