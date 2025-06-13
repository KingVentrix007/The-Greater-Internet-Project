import numpy as np
from datetime import datetime
import statistics

def detect_bottlenecks(gaps):
    if not gaps:
        return [], 0, 0, 0, 0
    gaps = np.array(gaps)
    Q1 = np.percentile(gaps, 25)
    Q3 = np.percentile(gaps, 75)
    IQR = Q3 - Q1
    upper_threshold = Q3 + 1.5 * IQR
    bottlenecks = [gap for gap in gaps if gap > upper_threshold]
    return bottlenecks, upper_threshold, Q1, Q3, IQR

def auto_split_sections(lines):
    sections = []
    current = []
    prev_type = None
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) != 3:
            continue
        pkt_type = parts[1].strip()
        if prev_type is not None and pkt_type != prev_type:
            sections.append(current)
            current = []
        current.append(line.strip())
        prev_type = pkt_type
    if current:
        sections.append(current)
    return sections

def process_section(section):
    hops, times = [], []
    for line in section:
        parts = line.strip().split(":")
        if len(parts) != 3:
            continue
        node, _, timestamp = parts
        hops.append(node.strip())
        times.append(float(timestamp.strip()))
    return hops, times

def analyze_path(hops, times):
    gaps = [times[i+1] - times[i] for i in range(len(times)-1)]
    bottlenecks, threshold, q1, q3, iqr = detect_bottlenecks(gaps)
    hop_info = []
    for i in range(len(gaps)):
        hop_info.append({
            "from": hops[i],
            "to": hops[i+1],
            "gap": gaps[i],
            "is_bottleneck": gaps[i] > threshold
        })
    return {
        "hops": hops,
        "gaps": gaps,
        "total_delay": sum(gaps),
        "average_gap": statistics.mean(gaps) if gaps else 0,
        "threshold": threshold,
        "q1": q1,
        "q3": q3,
        "iqr": iqr,
        "hop_info": hop_info
    }

def main():
    with open("time.txt", "r") as file:
        raw_lines = file.readlines()

    sections = auto_split_sections(raw_lines)
    paired_paths = []
    total_rtt = 0

    i = 0
    while i < len(sections) - 1:
        f_section = sections[i]
        r_section = sections[i + 1]
        if "Forward" in f_section[0] and "Return" in r_section[0]:
            f_hops, f_times = process_section(f_section)
            r_hops, r_times = process_section(r_section)

            forward_data = analyze_path(f_hops, f_times)
            return_data = analyze_path(r_hops, r_times)

            processing_delay = r_times[0] - f_times[-1]  # NEW: Server Processing Time
            rtt = forward_data["total_delay"] + return_data["total_delay"]
            total_rtt += rtt

            paired_paths.append({
                "forward": forward_data,
                "return": return_data,
                "rtt": rtt,
                "processing_delay": processing_delay
            })
            i += 2
        else:
            i += 1

    cur_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f"report_{cur_time}.log", "w") as report_file:
        report_file.write(f"EDOI-NET TIME REPORT (RTT PAIRED)\nGenerated: {cur_time}\n")
        report_file.write(f"Total Round-Trip Time Across All Pairs: {total_rtt:.6f}s\n\n")

        for idx, pair in enumerate(paired_paths):
            report_file.write(f"PAIR #{idx + 1}\n{'='*50}\n")

            # --- Forward path ---
            f = pair["forward"]
            report_file.write("FORWARD PATH\n")
            report_file.write(" -> ".join(f["hops"]) + "\n")
            report_file.write(f"Total Delay: {f['total_delay']:.6f}s | Average: {f['average_gap']:.6f}s\n")
            report_file.write(f"IQR: Q1={f['q1']:.6f}, Q3={f['q3']:.6f}, IQR={f['iqr']:.6f}, Threshold={f['threshold']:.6f}s\n")
            for hop in f["hop_info"]:
                mark = "[!]" if hop["is_bottleneck"] else "[ ]"
                report_file.write(f"  {mark} {hop['from']} -> {hop['to']} : {hop['gap']:.6f}s\n")

            # --- Return path ---
            r = pair["return"]
            report_file.write("\nRETURN PATH\n")
            report_file.write(" -> ".join(r["hops"]) + "\n")
            report_file.write(f"Total Delay: {r['total_delay']:.6f}s | Average: {r['average_gap']:.6f}s\n")
            report_file.write(f"IQR: Q1={r['q1']:.6f}, Q3={r['q3']:.6f}, IQR={r['iqr']:.6f}, Threshold={r['threshold']:.6f}s\n")
            for hop in r["hop_info"]:
                mark = "[!]" if hop["is_bottleneck"] else "[ ]"
                report_file.write(f"  {mark} {hop['from']} -> {hop['to']} : {hop['gap']:.6f}s\n")

            # --- Round-trip + Processing Delay ---
            report_file.write(f"\nSERVER PROCESSING TIME: {pair['processing_delay']:.6f}s\n")
            report_file.write(f"ROUND-TRIP TIME: {pair['rtt']:.6f}s\n")
            report_file.write(f"{'-'*50}\n\n")

    print(f"[✓] Report saved as: report_{cur_time}.log")

main()