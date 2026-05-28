#!/usr/bin/env python3
"""
ULTIMATE RTCStats Analyzer
Complete analysis: ICE, Network Quality, Simulcast, Layer Switching, Correlation, Architecture Detection and Codecs
"""

import json
import sys
import os
import csv
import io
from datetime import datetime

# CONFIGURATION
DEFAULT_FILEPATH = r"C:\Users\andri\OneDrive\Desktop\Master\Log Files\rtcstats_dump_discord_group_call.json"

def extract_platform_name(filepath):
    """Extract platform name from filename"""
    import os
    filename = os.path.basename(filepath)
    name = filename.replace('rtcstats_dump_', '').replace('.json', '')
    return name if name else 'Unknown'

def make_output_folder(filepath):
    """Create (or reuse) <platform>_analysis folder next to the input file."""
    base_dir = os.path.dirname(os.path.abspath(filepath))
    filename = os.path.basename(filepath)
    platform = filename.replace('rtcstats_dump_', '').replace('.json', '')
    folder   = os.path.join(base_dir, f'{platform}_analysis')
    if not os.path.exists(folder):
        os.makedirs(folder)
    return folder, platform

def write_outputs(folder, platform, txt_content, data_dict):
    """Write .txt, .json, .csv into the output folder."""
    base = os.path.join(folder, f'{platform}_results')

    # TXT
    with open(base + '.txt', 'w', encoding='utf-8') as f:
        f.write(txt_content)

    # JSON
    with open(base + '.json', 'w', encoding='utf-8') as f:
        json.dump(data_dict, f, indent=2)

    # CSV - one summary row
    fieldnames = [
        'platform', 'connection_type',
        'avg_jitter_ms', 'avg_rtt_ms', 'packet_loss_pct',
        'simulcast_layers_active', 'simulcast_layers_total',
        'layer_switches', 'architecture', 'architecture_confidence',
        'inbound_ssrcs', 'outbound_ssrcs', 'simulcast_in_sdp',
    ]
    with open(base + '.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({k: data_dict.get(k, '') for k in fieldnames})

    print(f"\n  Saved: {base}.txt")
    print(f"  Saved: {base}.json")
    print(f"  Saved: {base}.csv")

def analyze_complete(filepath):

    """Complete analysis with correlation between metrics and switches"""
    
    # Load file
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        out(f"ERROR: File not found: {filepath}")
        return
    
    platform = extract_platform_name(filepath)
    folder, _ = make_output_folder(filepath)

    # Buffer captures output for .txt while still printing to terminal
    buf = io.StringIO()
    def out(text=''):
        print(text)
        buf.write(str(text) + '\n')

    # HEADER
    out("=" * 80)
    out("ULTIMATE RTCStats ANALYSIS")
    out("=" * 80)
    out(f"Platform: {platform}")
    out(f"File: {filepath}")
    out(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out("=" * 80)
    out()

    # PART 1: ICE CANDIDATE GATHERING
    out("=" * 80)
    out("1. ICE CANDIDATE GATHERING")
    out("=" * 80)
    out()
    
    candidates = {'host': [], 'srflx': [], 'relay': []}
    
    for line in lines[2:]:
        try:
            event = json.loads(line.strip().rstrip(','))
            if (event[0] == 'addIceCandidate' or event[0] == 'onicecandidate') and len(event) > 2:
                cand_data = event[2]
                cand_str = cand_data.get('candidate', '')
                if not cand_str:
                    continue
                
                parts = cand_str.split()
                ip = parts[4] if len(parts) > 4 else ""
                
                is_turn_server = (
                    ip.startswith('142.250.') or ip.startswith('142.251.') or
                    ip.startswith('74.125.') or ip.startswith('172.217.') or
                    (not ip.startswith('192.168.') and not ip.startswith('10.') and
                     not ip.startswith('172.16.') and not ip.startswith('172.31.') and
                     not ip.startswith('127.') and 'typ host' in cand_str and
                     (':3478' in cand_str or ':19305' in cand_str))
                )
                
                if 'typ relay' in cand_str or is_turn_server:
                    candidates['relay'].append(cand_str)
                elif 'typ srflx' in cand_str:
                    candidates['srflx'].append(cand_str)
                elif 'typ host' in cand_str:
                    candidates['host'].append(cand_str)
        except:
            continue
    
    # Display ICE results
    for ctype, clist in [('host', 'Host (Local)'), ('srflx', 'Server Reflexive (STUN)'), ('relay', 'Relay (TURN)')]:
        if candidates[ctype]:
            out(f"{clist}: {len(candidates[ctype])}")
            for cand in candidates[ctype][:2]:
                parts = cand.split()
                if len(parts) >= 5:
                    ip, port = parts[4], parts[5] if len(parts) > 5 else "?"
                    proto = 'UDP' if 'udp' in cand.lower() else 'TCP'
                    out(f"  - {ip}:{port} ({proto})")
            if len(candidates[ctype]) > 2:
                out(f"  ... and {len(candidates[ctype]) - 2} more")
            out()
    
    total_candidates = sum(len(v) for v in candidates.values())
    out(f"Total Candidates: {total_candidates}")
    
    if len(candidates['relay']) > 0 and len(candidates['srflx']) == 0:
        connection_type = "TURN RELAY (restricted network)"
    elif len(candidates['srflx']) > 0:
        connection_type = "PEER-TO-PEER capable"
    elif len(candidates['host']) > 0 and total_candidates == len(candidates['host']):
        connection_type = "LOCAL NETWORK only"
    else:
        connection_type = "MIXED/UNKNOWN"
    
    out(f"Connection Type: {connection_type}")
    out()

    # PART 2: NETWORK QUALITY METRICS (WITH TIMELINE)
    out("=" * 80)
    out("2. NETWORK QUALITY METRICS")
    out("=" * 80)
    out()
    
    # Parse getStats events
    events = []
    sdp_lines = []
    for line in lines[2:]:
        try:
            event = json.loads(line.strip().rstrip(','))
            if event[0] == 'getStats':
                events.append(event[2])
            elif event[0] in ('createOfferOnSuccess', 'setRemoteDescription', 'setLocalDescription') and len(event) > 2:
                sdp_lines.append(event)
        except:
            continue
    
    out(f"Analyzed {len(events)} getStats events")
    out()
    
    # Collect metrics WITH TIMELINE
    quality_timeline = []
    audio_metrics = {'jitter': [], 'rtt': [], 'packets_lost': None, 'packets_sent': None}
    video_metrics = {'packets_sent': None, 'bytes_sent': None, 'nack_count': None}
    
    for i, event in enumerate(events):
        timestamp = i
        metrics_at_time = {'timestamp': timestamp, 'jitter': None, 'rtt': None, 'bitrate': 0}
        
        for key, value in event.items():
            if not isinstance(value, dict):
                continue
            
            # Audio metrics
            if value.get('type') == 'inbound-rtp' and value.get('kind') == 'audio':
                jitter = value.get('jitter')
                if jitter is not None:
                    jitter_ms = jitter * 1000
                    audio_metrics['jitter'].append(jitter_ms)
                    metrics_at_time['jitter'] = jitter_ms
                
                audio_metrics['packets_lost'] = value.get('packetsLost', 0)

            if value.get('type') == 'remote-inbound-rtp' and value.get('kind') == 'audio':
                rtt = value.get('roundTripTime')
                if rtt is not None:
                    rtt_ms = rtt * 1000
                    audio_metrics['rtt'].append(rtt_ms)
                    metrics_at_time['rtt'] = rtt_ms
            
            if value.get('type') == 'outbound-rtp' and value.get('kind') == 'audio':
                audio_metrics['packets_sent'] = value.get('packetsSent')
            
            # Video metrics
            if value.get('type') == 'outbound-rtp' and value.get('kind') == 'video':
                video_metrics['packets_sent'] = value.get('packetsSent')
                video_metrics['bytes_sent'] = value.get('bytesSent')
                video_metrics['nack_count'] = value.get('nackCount', 0)
        
        quality_timeline.append(metrics_at_time)
    
    # Display audio metrics
    out("AUDIO QUALITY:")
    out("-" * 80)
    if audio_metrics['jitter']:
        avg_jitter = sum(audio_metrics['jitter']) / len(audio_metrics['jitter'])
        min_jitter = min(audio_metrics['jitter'])
        max_jitter = max(audio_metrics['jitter'])
        out(f"Jitter:       {avg_jitter:.2f} ms (avg), range: {min_jitter:.2f} - {max_jitter:.2f} ms")
    
    if audio_metrics['rtt']:
        avg_rtt = sum(audio_metrics['rtt']) / len(audio_metrics['rtt'])
        min_rtt = min(audio_metrics['rtt'])
        max_rtt = max(audio_metrics['rtt'])
        out(f"RTT:          {avg_rtt:.2f} ms (avg), range: {min_rtt:.2f} - {max_rtt:.2f} ms")
    
    if audio_metrics['packets_sent'] and audio_metrics['packets_lost'] is not None:
        loss_pct = (audio_metrics['packets_lost'] / audio_metrics['packets_sent']) * 100
        out(f"Packet Loss:  {loss_pct:.4f}% ({audio_metrics['packets_lost']}/{audio_metrics['packets_sent']:,})")
    out()
    
    # Display video metrics
    out("VIDEO QUALITY:")
    out("-" * 80)
    if video_metrics['packets_sent']:
        out(f"Packets Sent: {video_metrics['packets_sent']:,}")
    if video_metrics['bytes_sent']:
        mb_sent = video_metrics['bytes_sent'] / (1024 * 1024)
        out(f"Data Sent:    {mb_sent:.2f} MB")
    if video_metrics['nack_count'] is not None:
        out(f"NACK Count:   {video_metrics['nack_count']} (retransmission requests)")
    out()

    # PART 3: SIMULCAST LAYER ANALYSIS + SWITCH DETECTION
    out("=" * 80)
    out("3. SIMULCAST & LAYER SWITCHING ANALYSIS")
    out("=" * 80)
    out()
    
    # Track both outbound and inbound layers OVER TIME
    outbound_timeline = []
    inbound_timeline = []
    
    for i, event in enumerate(events):
        timestamp = i
        out_layers = {}
        in_layers = {}
        
        for key, value in event.items():
            if not isinstance(value, dict):
                continue
            
            if value.get('type') == 'outbound-rtp' and value.get('kind') == 'video':
                ssrc = value.get('ssrc')
                if ssrc:
                    out_layers[ssrc] = {
                        'bytes': value.get('bytesSent', 0),
                        'packets': value.get('packetsSent', 0)
                    }
            
            if value.get('type') == 'inbound-rtp' and value.get('kind') == 'video':
                ssrc = value.get('ssrc')
                if ssrc:
                    in_layers[ssrc] = {
                        'bytes': value.get('bytesReceived', 0),
                        'packets': value.get('packetsReceived', 0)
                    }
        
        outbound_timeline.append({'timestamp': timestamp, 'layers': out_layers})
        inbound_timeline.append({'timestamp': timestamp, 'layers': in_layers})
    
    # Analyze layer activity and detect switches
    def analyze_layers(timeline, direction):
        """Analyze layer activity over time"""
        layer_data = {}
        switches = []
        prev_active = None
        
        for i in range(1, len(timeline)):
            prev = timeline[i-1]
            curr = timeline[i]
            timestamp = curr['timestamp']
            
            # Find most active layer
            max_increase = 0
            active_ssrc = None
            active_bitrate = 0
            
            for ssrc in curr['layers']:
                if ssrc in prev['layers']:
                    increase = curr['layers'][ssrc]['bytes'] - prev['layers'][ssrc]['bytes']
                    if increase > max_increase:
                        max_increase = increase
                        active_ssrc = ssrc
                        active_bitrate = (increase * 8) / 1000  # kbps
            
            # Track this layer
            if active_ssrc:
                if active_ssrc not in layer_data:
                    layer_data[active_ssrc] = {
                        'bytes': [],
                        'bitrates': [],
                        'active_times': []
                    }
                
                layer_data[active_ssrc]['bytes'].append(curr['layers'][active_ssrc]['bytes'])
                layer_data[active_ssrc]['bitrates'].append(active_bitrate)
                layer_data[active_ssrc]['active_times'].append(timestamp)
            
            # Detect switch
            if active_ssrc and prev_active and active_ssrc != prev_active:
                switches.append({
                    'timestamp': timestamp,
                    'from_ssrc': prev_active,
                    'to_ssrc': active_ssrc,
                    'bitrate': active_bitrate
                })
            
            prev_active = active_ssrc
        
        return layer_data, switches
    
    # Analyze both directions
    out_layers, out_switches = analyze_layers(outbound_timeline, "OUTBOUND")
    in_layers, in_switches = analyze_layers(inbound_timeline, "INBOUND")
    
    # Display INBOUND (most relevant for you)
    if in_layers:
        out("INBOUND VIDEO (Received from Remote):")
        out("-" * 80)
        
        sorted_in = sorted(in_layers.items(), 
                          key=lambda x: x[1]['bytes'][-1] if x[1]['bytes'] else 0, 
                          reverse=True)
        
        layer_names = ["HIGH", "MEDIUM", "LOW"]
        for idx, (ssrc, data) in enumerate(sorted_in):
            name = layer_names[idx] if idx < len(layer_names) else f"Layer {idx+1}"
            total_mb = data['bytes'][-1] / (1024 * 1024) if data['bytes'] else 0
            avg_br = sum(data['bitrates']) / len(data['bitrates']) if data['bitrates'] else 0
            activity_pct = (len(data['active_times']) / len(events)) * 100
            
            out(f"  {name} (SSRC: {ssrc})")
            out(f"    Data Received: {total_mb:.2f} MB")
            out(f"    Avg Bitrate:   {avg_br:.0f} kbps")
            out(f"    Activity:      {activity_pct:.1f}%")
            out()
        
        if len(sorted_in) == 1:
            out("  Analysis: NO SIMULCAST (single quality stream)")
        else:
            active_count = sum(1 for _, data in sorted_in if len(data['active_times']) > len(events) * 0.1)
            out(f"  Layers Active: {active_count}/{len(sorted_in)}")
            if active_count == len(sorted_in):
                out("  Adaptation:    EXCELLENT - All layers active")
            elif active_count >= 2:
                out("  Adaptation:    GOOD - Multiple layers active")
            else:
                out("  Adaptation:    LIMITED - Single layer only")
        out()
    
    # LAYER SWITCH DETECTION WITH CORRELATION
    if in_switches:
        out("=" * 80)
        out("4. LAYER SWITCH EVENTS & CORRELATION ANALYSIS")
        out("=" * 80)
        out()
        out(f"Detected {len(in_switches)} layer switch events:")
        out("-" * 80)
        
        for i, switch in enumerate(in_switches, 1):
            ts = switch['timestamp']
            
            # Get network quality at switch time
            metrics_before = quality_timeline[ts-1] if ts > 0 else {}
            metrics_after = quality_timeline[ts] if ts < len(quality_timeline) else {}
            
            out(f"\nSwitch #{i} at Time {ts}s:")
            out(f"  Direction: SSRC {switch['from_ssrc']} -> {switch['to_ssrc']}")
            out(f"  New Bitrate: {switch['bitrate']:.0f} kbps")
            
            # Show correlated metrics
            out(f"\n  Network Quality at Switch:")
            if metrics_before.get('jitter') and metrics_after.get('jitter'):
                out(f"    Jitter:  {metrics_before['jitter']:.2f} -> {metrics_after['jitter']:.2f} ms")
            if metrics_before.get('rtt') and metrics_after.get('rtt'):
                out(f"    RTT:     {metrics_before['rtt']:.2f} -> {metrics_after['rtt']:.2f} ms")
            
            # Infer likely trigger
            out(f"\n  Likely Trigger:")
            if metrics_before.get('jitter', 0) > metrics_after.get('jitter', 0) + 0.1:
                out(f"    - Jitter decreased after switch (quality improved)")
            if switch['bitrate'] < 1000:
                out(f"    - Low bitrate suggests bandwidth constraint")
            else:
                out(f"    - Bandwidth adaptation to network conditions")
        
        out()
        out("-" * 80)
        
        # Switch frequency analysis
        if len(in_switches) > 1:
            intervals = [in_switches[i]['timestamp'] - in_switches[i-1]['timestamp'] 
                        for i in range(1, len(in_switches))]
            avg_interval = sum(intervals) / len(intervals)
            out(f"\nSwitch Frequency Analysis:")
            out(f"  Average interval: {avg_interval:.1f} seconds")
            out(f"  Shortest: {min(intervals)}s, Longest: {max(intervals)}s")
            
            freq_per_min = len(in_switches) / (len(events) / 60)
            out(f"  Frequency: {freq_per_min:.2f} switches/minute")
            
            if freq_per_min < 0.5:
                out(f"  Stability: EXCELLENT")
            elif freq_per_min < 2:
                out(f"  Stability: GOOD")
            elif freq_per_min < 5:
                out(f"  Stability: MODERATE")
            else:
                out(f"  Stability: POOR")
        out()
    else:
        if in_layers:
            out("No layer switches detected (stable connection)")
            out()

    # PART 4: MULTI-PARTY ARCHITECTURE DETECTION
    out("=" * 80)
    out("4. MULTI-PARTY ARCHITECTURE DETECTION")
    out("=" * 80)
    out()

    # Collect unique SSRCs per direction across all snapshots
    all_inbound_ssrcs  = set()
    all_outbound_ssrcs = set()
    simulcast_rids     = set()
    inbound_video_per_snapshot = []

    for event in events:
        snapshot_inbound_video = 0
        for key, value in event.items():
            if not isinstance(value, dict):
                continue
            report_type = value.get('type', '')

            if report_type == 'inbound-rtp':
                ssrc = value.get('ssrc')
                if ssrc:
                    all_inbound_ssrcs.add(ssrc)
                if value.get('kind') == 'video':
                    snapshot_inbound_video += 1
                rid = value.get('rid')
                if rid:
                    simulcast_rids.add(rid)

            elif report_type == 'outbound-rtp':
                ssrc = value.get('ssrc')
                if ssrc:
                    all_outbound_ssrcs.add(ssrc)
                rid = value.get('rid')
                if rid:
                    simulcast_rids.add(rid)

        if snapshot_inbound_video > 0:
            inbound_video_per_snapshot.append(snapshot_inbound_video)

    inbound_count  = len(all_inbound_ssrcs)
    outbound_count = len(all_outbound_ssrcs)
    max_concurrent_inbound_video = max(inbound_video_per_snapshot) if inbound_video_per_snapshot else 0

    # Inspect SDP for simulcast / RID lines
    simulcast_in_sdp = False
    rid_in_sdp       = False
    all_sdp_text     = ''

    for sdp_event in sdp_lines:
        try:
            sdp_obj = sdp_event[2]
            if isinstance(sdp_obj, dict):
                all_sdp_text += sdp_obj.get('sdp', '')
        except (IndexError, TypeError):
            pass

    if 'a=simulcast:' in all_sdp_text:
        simulcast_in_sdp = True
    if 'a=rid:' in all_sdp_text:
        rid_in_sdp = True
        for sdp_line in all_sdp_text.splitlines():
            sdp_line = sdp_line.strip()
            if sdp_line.startswith('a=rid:'):
                rid_val = sdp_line.split(' ')[0].replace('a=rid:', '')
                if rid_val:
                    simulcast_rids.add(rid_val)

    # Print raw numbers
    out(f"Inbound  SSRCs (streams you receive) : {inbound_count}")
    out(f"Outbound SSRCs (streams you send)    : {outbound_count}")
    out(f"Max concurrent inbound video streams : {max_concurrent_inbound_video}")
    out(f"Simulcast RIDs detected              : {sorted(simulcast_rids) or 'None'}")
    out(f"Simulcast in SDP (a=simulcast:)      : {'Yes' if simulcast_in_sdp else 'No'}")
    out(f"RID lines in SDP (a=rid:)            : {'Yes' if rid_in_sdp else 'No'}")
    out()

    # Build evidence list
    evidence = []

    if inbound_count == 0:
        evidence.append("No inbound-rtp entries - capture may be solo/1-on-1 or call not active")
    elif inbound_count == 1:
        evidence.append("1 unique inbound SSRC -> MCU-style: server sends a single mixed stream")
    else:
        evidence.append(f"{inbound_count} unique inbound SSRCs -> SFU-style: individual streams forwarded per participant")

    if outbound_count == 1:
        evidence.append("1 outbound SSRC -> single quality upload (no simulcast in stats)")
    elif outbound_count > 1:
        evidence.append(f"{outbound_count} outbound SSRCs -> simulcast layers or multiple tracks being sent")

    if len(simulcast_rids) >= 2:
        evidence.append(f"Simulcast RIDs {sorted(simulcast_rids)} -> SFU with multiple quality layers (high/medium/low)")

    if simulcast_in_sdp:
        evidence.append("a=simulcast: in SDP -> platform explicitly negotiates simulcast upload")

    if max_concurrent_inbound_video > 1:
        evidence.append(f"Up to {max_concurrent_inbound_video} concurrent inbound video streams in one snapshot -> SFU confirmed")

    if outbound_count >= 3 and inbound_count >= 2:
        evidence.append("High inbound AND outbound SSRC count -> possible Mesh topology (verify in Wireshark: traffic to many IPs)")

    out("Evidence:")
    for e in evidence:
        out(f"  * {e}")
    out()

    # Verdict
    if inbound_count == 0:
        verdict    = "Inconclusive (solo/1-on-1 call - no multi-party data)"
        confidence = "N/A"
        note = "Re-capture with 3+ participants to get meaningful architecture data."

    elif inbound_count == 1 and not simulcast_in_sdp and len(simulcast_rids) < 2:
        verdict    = "MCU (Multipoint Control Unit)"
        confidence = "Medium"
        note = ("Single inbound stream regardless of participant count is the MCU hallmark. "
                "Confirm by adding more participants and checking the inbound SSRC count stays at 1.")

    elif inbound_count >= 2 and (simulcast_in_sdp or len(simulcast_rids) >= 2):
        verdict    = "SFU (Selective Forwarding Unit) with Simulcast"
        confidence = "High"
        note = ("Multiple inbound streams + simulcast upload = strong SFU indicators. "
                "Each participant stream is forwarded independently; "
                "you upload multiple quality layers so the server picks the best one per subscriber.")

    elif inbound_count >= 2:
        verdict    = "SFU (Selective Forwarding Unit)"
        confidence = "Medium-High"
        note = ("Multiple independent inbound streams point to SFU. "
                "No simulcast lines found - platform may use fixed bitrate or simulcast SDP was absent.")

    elif inbound_count == 1 and (simulcast_in_sdp or len(simulcast_rids) >= 2):
        verdict    = "Likely MCU with Simulcast Upload"
        confidence = "Medium"
        note = ("Uploading simulcast layers but receiving only one mixed stream. "
                "Some MCU platforms still request simulcast to pick the best quality for mixing.")

    else:
        verdict    = "Unknown"
        confidence = "Low"
        note = "Not enough data to determine architecture."

    out(f"Verdict:    {verdict}")
    out(f"Confidence: {confidence}")
    out()
    out(f"Note: {note}")
    out()
    out("Architecture Reference:")
    out("  Mesh   - Each peer connects directly to every other peer.")
    out("           Multiple DTLS handshakes; media traffic to many distinct IPs.")
    out("  SFU    - Server forwards each stream individually to subscribers.")
    out("           N inbound SSRCs for N participants; simulcast upload common.")
    out("  MCU    - Server decodes, mixes, re-encodes all streams into one.")
    out("           Always 1 inbound SSRC regardless of how many participants.")
    out("  Hybrid - Combination (e.g. P2P for 1:1 calls, SFU for group calls).")
    out()

    # CODEC SECTION BREAK - ACTUAL CODE AT THE BOTTOM
    out("=" * 80)
    out("5. CODEC EXTRACTION")
    out("=" * 80)
    codec_results = extract_codecs(lines, out)

    # FINAL SUMMARY
    out("=" * 80)
    out("SUMMARY")
    out("=" * 80)
    out()
    out(f"Platform:          {platform}")
    out(f"Connection:        {connection_type}")
    
    if codec_results: 
        if codec_results['audio_names']: 
            out(f"Audio Codec:       {', '.join(codec_results['audio_names'])}")
        if codec_results['video_names']: 
            out(f"Video Codec:       {', '.join(codec_results['video_names'])}") 
    
    if audio_metrics['jitter']:
        out(f"Audio Jitter:      {sum(audio_metrics['jitter'])/len(audio_metrics['jitter']):.2f} ms")
    if audio_metrics['rtt']:
        out(f"Audio RTT:         {sum(audio_metrics['rtt'])/len(audio_metrics['rtt']):.2f} ms")
    if audio_metrics['packets_sent'] and audio_metrics['packets_lost'] is not None:
        out(f"Packet Loss:       {(audio_metrics['packets_lost']/audio_metrics['packets_sent'])*100:.4f}%")
    
    if in_layers:
        active = sum(1 for _, d in in_layers.items() if len(d['active_times']) > len(events)*0.1)
        out(f"Simulcast Layers:  {active}/{len(in_layers)} active")
    
    if in_switches:
        out(f"Layer Switches:    {len(in_switches)} events")

    out(f"Architecture:      {verdict} ({confidence} confidence)")
    out()

    out("=" * 80)
    out("Analysis Complete!")
    out("=" * 80)

    # WRITE OUTPUT FILES
    print()
    print("OUTPUT FILES")
    print("-" * 80)

    avg_jitter = sum(audio_metrics["jitter"])/len(audio_metrics["jitter"]) if audio_metrics["jitter"] else None
    avg_rtt    = sum(audio_metrics["rtt"])/len(audio_metrics["rtt"]) if audio_metrics["rtt"] else None
    loss_pct   = None
    if audio_metrics["packets_sent"] and audio_metrics["packets_lost"] is not None:
        loss_pct = round((audio_metrics["packets_lost"] / audio_metrics["packets_sent"]) * 100, 4)

    sim_active = sim_total = 0
    if in_layers:
        sim_total  = len(in_layers)
        sim_active = sum(1 for _, d in in_layers.items() if len(d["active_times"]) > len(events) * 0.1)

    data_dict = {
        "platform":                   platform,
        "file":                       filepath,
        "analyzed_at":                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "connection_type":            connection_type,
        "avg_jitter_ms":              round(avg_jitter, 2) if avg_jitter is not None else None,
        "avg_rtt_ms":                 round(avg_rtt, 2) if avg_rtt is not None else None,
        "packet_loss_pct":            loss_pct,
        "simulcast_layers_active":    sim_active,
        "simulcast_layers_total":     sim_total,
        "layer_switches":             len(in_switches),
        "architecture":               verdict,
        "architecture_confidence":    confidence,
        "inbound_ssrcs":              inbound_count,
        "outbound_ssrcs":             outbound_count,
        "simulcast_in_sdp":           simulcast_in_sdp,
    }

    write_outputs(folder, platform, buf.getvalue(), data_dict)

# PART 5: CODEC EXTRACTION
def extract_codecs(lines, out=print):
    """Extract codec info from first SDP offer and answer"""
    
    first_offer_sdp = None
    first_answer_sdp = None
    
    for line in lines[2:]:
        if first_offer_sdp and first_answer_sdp:
            break
        try:
            event = json.loads(line.strip().rstrip(','))
            if event[0] == 'createOfferOnSuccess' and not first_offer_sdp:
                first_offer_sdp = event[2]['sdp']
            elif event[0] in ('setRemoteDescription', 'setRemoteDescriptionOnSuccess', 'setLocalDescription', 'createAnswerOnSuccess') and not first_answer_sdp:
                if isinstance(event[2], dict) and event[2].get('type') == 'answer':
                    first_answer_sdp = event[2]['sdp']
        except (IndexError, KeyError, TypeError, json.JSONDecodeError):
            continue
    
    def parse_sdp_codecs(sdp):
        if not sdp:
            return {}
        
        codecs = {}
        lines = sdp.replace('\\r\\n', '\n').replace('\r\n', '\n').split('\n')
        
        for line in lines:
            if line.startswith('a=rtpmap:'):
                try:
                    pt = line.split(':')[1].split()[0]
                    codec_str = line.split()[1]
                    codecs[pt] = {'codec': codec_str, 'fmtp': None, 'rtcp_fb': []}
                except IndexError:
                    continue
            elif line.startswith('a=fmtp:'):
                try:
                    pt = line.split(':')[1].split()[0]
                    params = line.split(maxsplit=1)[1].split(maxsplit=1)
                    if len(params) > 1 and pt in codecs:
                        codecs[pt]['fmtp'] = params[1]
                except (IndexError, KeyError):
                    continue
            elif line.startswith('a=rtcp-fb:'):
                try:
                    pt = line.split(':')[1].split()[0]
                    fb = ' '.join(line.split()[1:])
                    if pt in codecs:
                        codecs[pt]['rtcp_fb'].append(fb)
                except (IndexError, KeyError):
                    continue
        
        return codecs

    offer_codecs = parse_sdp_codecs(first_offer_sdp)
    answer_codecs = parse_sdp_codecs(first_answer_sdp)
    
    used_audio = None
    used_video = None

    for line in lines[2:]: 
        if used_audio and used_video:
            break
        try: 
            event = json.loads(line.strip().rstrip(','))
            if event[0] == 'getStats': 
                stats = event[2]
                for key, value in stats.items(): 
                    if not isinstance(value, dict): 
                        continue
                    cid = value.get('codecId', '')
                    if not cid:
                        continue
                    parts = cid.split('_')
                    if len(parts) < 2:
                        continue
                    pt = parts[1]

                    if value.get('type') == 'outbound-rtp' and value.get('kind') == 'audio' and used_audio is None: 
                        if pt in answer_codecs:
                            used_audio = answer_codecs[pt]['codec'].split('/')[0]
                    if value.get('type') == 'inbound-rtp' and value.get('kind') == 'audio' and used_audio is None:
                        if pt in answer_codecs:
                            used_audio = answer_codecs[pt]['codec'].split('/')[0]
                    if value.get('type') == 'outbound-rtp' and value.get('kind') == 'video' and used_video is None:
                        if pt in answer_codecs:
                            used_video = answer_codecs[pt]['codec'].split('/')[0]
                    if value.get('type') == 'inbound-rtp' and value.get('kind') == 'video' and used_video is None:
                        if pt in answer_codecs:
                            used_video = answer_codecs[pt]['codec'].split('/')[0]           
        except:
            continue

    def categorize(codecs):
        audio, video, other = {}, {}, {}
        for pt, info in codecs.items():
            if not info['codec']:
                continue
            if '/90000' in info['codec']:
                video[pt] = info
            elif any(x in info['codec'].lower() for x in ['opus', 'pcmu', 'pcma', 'g722', 'telephone']):
                audio[pt] = info
            else:
                other[pt] = info
        return audio, video, other

    for label, codecs in [("OFFERED (SDP Offer)", offer_codecs),
                           ("NEGOTIATED (SDP Answer)", answer_codecs)]:
        audio, video, other = categorize(codecs)
        out(f"\n--- {label} ---")
        
        out("\n  AUDIO:")
        if audio:
            for pt, info in audio.items():
                out(f"    PT {pt}: {info['codec']}")
                if info['fmtp']:
                    out(f"           fmtp: {info['fmtp']}")
                if info['rtcp_fb']:
                    out(f"           rtcp-fb: {', '.join(info['rtcp_fb'])}")
        else:
            out("    None found")

        out("\n  VIDEO:")
        if video:
            for pt, info in video.items():
                out(f"    PT {pt}: {info['codec']}")
                if info['fmtp']:
                    out(f"           fmtp: {info['fmtp']}")
                if info['rtcp_fb']:
                    out(f"           rtcp-fb: {', '.join(info['rtcp_fb'])}")
        else:
            out("    None found")

        if other:
            out("\n  OTHER:")
            for pt, info in other.items():
                out(f"    PT {pt}: {info['codec']}")
                if info['fmtp']:
                    out(f"           fmtp: {info['fmtp']}")

    audio_cat, video_cat, _ = categorize(answer_codecs) 
    
    return {
        'audio_names': [used_audio] if used_audio else list(set(info['codec'] for _, info in audio_cat.items())), 
        'video_names': [used_video] if used_video else list(set(info['codec'] for _, info in video_cat.items() if 'rtx' not in info['codec'].lower()))
    }

# Main
if __name__ == "__main__":
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = DEFAULT_FILEPATH
    
    analyze_complete(filepath)
