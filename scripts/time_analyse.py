import numpy as np
from datetime import datetime, timezone, timedelta
import statistics
import time
def detect_bottlenecks(ugaps):
    gaps = np.array(ugaps)
    Q1 = np.percentile(gaps,25)
    Q3 = np.percentile(gaps,75)
    IQRv = Q3 - Q1
    upper_threshold = Q3+1.5*IQRv
    bottlenecks = [gap for gap in gaps if gap > upper_threshold]
    return bottlenecks,upper_threshold

def main():
    # print("Ruun")
    file = open("time.txt","r")
    # all_lines = file.read()
    lines_temp = file.readlines()
    # print(lines_temp)
    # divider = "-"
    large_parts = []
    small = []
    main_total = 0
    for w in lines_temp:
        # print(w)
        if(w.startswith("--")):
            # print(">>")
            large_parts.append(small.copy())
            # print(small)
            small.clear()
        else:
            small.append(w)
    large_parts.append(small)
    # print(large_parts)
    all_paths = []
    all_times = []
    all_average = []
    for section in large_parts:
        # print(section)
        print("----")
        lines = section
        path = []
        times = []
        gaps = [] 
        for line in lines:
            parts = line.split(":")
            # print()
            node_name = parts[0]
            packet_type = parts[1]
            received_time = float(parts[2])
            path.append(node_name)
            times.append(received_time)
        for i in range(len(times)-1):
            gap = times[i+1]-times[i]
            # print(gap)
            gaps.append(gap)
        total_delay = 0
        bottlenecks,threshold = detect_bottlenecks(gaps)
        for q in range(len(path)-1):
            total_delay += gaps[q]
            if(gaps[q] in bottlenecks):
                print("[!]",end="")
            else:
                print("[ ]",end="")
            print(f"{path[q]} -> {path[q+1]}: {gaps[q]}")
        print(f"Total delay: {total_delay}")
        all_paths.append(path)
        all_times.append(total_delay)
        all_average.append(statistics.mean(gaps))
        main_total += total_delay
    file.close()
    print("---")
    print(f"Total round time: {main_total}")
    cur_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = open(f"report_{cur_time}.log","w")
    report_file.write(f"EDOI-NET Time report\nGenerated at {cur_time}\n---\n")
    for t in range(len(all_paths)):
        cur_path = "->".join(all_paths[t])
        cur_delay = all_times[t]
        cur_avr = all_average[t]
        report_line = f"Path: {cur_path}. \nDelay: {cur_delay}.\nAverage node delay: {cur_avr}\n---\n"
        report_file.write(report_line)
    report_file.close()
    # forwad_path = 
    # print("Done")
main()

