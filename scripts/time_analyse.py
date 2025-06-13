import numpy as np
from datetime import datetime
import statistics
from collections import defaultdict

def detect_bottlenecks(gaps):
    gaps = np.array(gaps)
    Q1 = np.percentile(gaps, 25)
    Q3 = np.percentile(gaps, 75)
    IQR = Q3 - Q1
    upper_threshold = Q3 + 1.5 * IQR
    bottlenecks = [gap for gap in gaps if gap > upper_threshold]
    return bottlenecks, upper_threshold, Q1, Q3, IQR

def auto_split_sections(lines):
    sections = []
    current_section = []

    prev_type = None
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) != 3:
            continue

        packet_type = parts[1].strip()

        if prev_type is not None and packet_type != prev_type:
            # Type changed – split section
            if current_section:
                sections.append(current_section)
                current_section = []

        current_section.append(line.strip())
        prev_type = packet_type

    if current_section:
        sections.append(current_section)

    return sections

def process_section(lines):
    hops, types, times = [], [], []
    for line in lines:
        parts = line.split(":")
        if len(parts) != 3:
            continue
        node, ptype, timestamp = parts
        hops.append(node.strip())
        types.append(ptype.strip())
        times.append(float(timestamp.strip()))
    return hops, types, times

def main():
    with open("time.txt", "r") as file:
        raw_lines = file.readlines()

    sections = auto_split_sections(raw_lines)
    path_data = defaultdict(list)
    total_network_time = 0

    for section in sections:
        hops, types, times = process_section(section)
        if not times or len(times) < 2:
            continue

        path_type = types[0] if all(t == types[0] for t in types) else "Mixed"
        gaps = [times[i+1] - times[i] for i in range(len(times)-1)]

        total_delay = sum(gaps)
        avg_gap = statistics.mean(gaps)
        bottlenecks, threshold, q1, q3, iqr = detect_bottlenecks(gaps)

        hop_info = []
        for i in range(len(gaps)):
            hop_info.append({
                "from": hops[i],
                "to": hops[i+1],
                "gap": gaps[i],
                "is_bottleneck": gaps[i] > threshold
            })

        path_data[path_type].append({
            "hops": hops,
            "gaps": gaps,
            "total_delay": total_delay,
            "average_gap": avg_gap,
            "hop_info": hop_info,
            "threshold": threshold,
            "q1": q1,
            "q3": q3,
            "iqr": iqr
        })

        total_network_time += total_delay

    cur_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f"report_{cur_time}.log", "w") as report_file:
        report_file.write(f"EDOI-NET TIME REPORT\nGenerated: {cur_time}\nTotal Network Time: {total_network_time:.6f}s\n\n")

        for ptype, paths in path_data.items():
            report_file.write(f" Path Type: {ptype}\n{'='*40}\n")
            for idx, path in enumerate(paths):
                hop_desc = " -> ".join(path["hops"])
                report_file.write(f"Path #{idx + 1}: {hop_desc}\n")
                report_file.write(f"Total Delay: {path['total_delay']:.6f}s\n")
                report_file.write(f"Average Hop Delay: {path['average_gap']:.6f}s\n")
                report_file.write(f"Delay Threshold (IQR-based): {path['threshold']:.6f}s\n")
                report_file.write(f"IQR Stats: Q1={path['q1']:.6f}, Q3={path['q3']:.6f}, IQR={path['iqr']:.6f}\n")

                for hop in path["hop_info"]:
                    mark = "[!]" if hop["is_bottleneck"] else "[ ]"
                    report_file.write(f"  {mark} {hop['from']} -> {hop['to']} : {hop['gap']:.6f}s\n")
                report_file.write("---\n")
            report_file.write("\n")

    print(f"[✓] Report saved to: report_{cur_time}.log")

if __name__ == "__main__":
    main()
