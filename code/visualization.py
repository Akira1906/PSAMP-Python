import matplotlib.pyplot as plt
import numpy as np
import pyshark
from scipy.interpolate import interp1d


def visualize_pr(data_filename, selectionSequenceId):

    filtered_packets = []
    parsed_packets = []
    times = []
    alternate_times = True
    with open(data_filename) as f:
        for line in f:
            if len(line) > 0:
                parts = line.split(':')
                if parts[0].startswith('f'):
                    filtered_packets.append(float(parts[1]))
                else:
                    parsed_packets.append(float(parts[1]))
                if alternate_times:
                    times.append(float(parts[0][1:]))
                alternate_times = not alternate_times

    # cut off inactive time in the beginning and end
    for _ in range(2):
        filtered_packets.reverse()
        parsed_packets.reverse()
        times.reverse()
        i = 0
        while len(filtered_packets) > i and filtered_packets[i] == 0.0 and parsed_packets[i] == 0.0:
            i += 1
        filtered_packets = filtered_packets[i:]
        parsed_packets = parsed_packets[i:]
        times = times[i:]

    fig, ax = plt.subplots(figsize=(14, 10))
    ax.plot(times, parsed_packets, label='Parsed Packets')
    ax.plot(times, filtered_packets, label='Filtered Packets')
    ax.axhline(np.mean(parsed_packets), color='blue',
               linestyle='dashed', label='Parsed Packets Average')
    ax.axhline(np.mean(filtered_packets), color='orange',
               linestyle='dashed', label='Filtered Packets Average')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Packets per Second')
    ax.set_title(
        'Parsed and Filtered Packets (SelectionProcess: ' + str(selectionSequenceId)+")")
    fig.canvas.manager.set_window_title(
        'Parsed and Filtered Packets ' + str(selectionSequenceId))
    ax.set_ylim(ymin=0)
    ax.set_xlim(xmin=0)
    # set font of all elements to size 22
    plt.rc('font', size=14)
    plt.tight_layout(pad=3, w_pad=0, h_pad=0)
    # Shrink current axis by 20%
    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])

    # Put a legend to the right of the current axis
    ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    plt.savefig("experiment/nf-plot_pr.svg")


def visualize_pr_timestamps(data_filename, selectionSequenceId):

    timestamps = []
    with open(data_filename) as f:
        for line in f:
            if len(line) > 0:
                if line[0].startswith('t'):
                    timestamps.append(int(float(line[1:-1])))

    packetrates = []
    times = []

    last_t = timestamps[0]

    for t in timestamps[1:]:
        packetrates.append(1/(t-last_t) * 1e9)
        times.append((t - timestamps[0])/1e9)
        last_t = t

    fig, ax = plt.subplots(figsize=(14, 10))
    ax.plot(times, packetrates, label='Cam 1')
    ax.axhline(np.mean(packetrates), color='blue',
               linestyle='dashed', label='Cam 1 Average')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Packets per Second')
    ax.set_title(
        "Packet Rate Camera Flow 1")
    fig.canvas.manager.set_window_title(
        'Packet Rate from Timestamps ' + str(selectionSequenceId))
    ax.set_ylim(ymin=0)
    ax.set_xlim(0,60)
    # plt.tight_layout(pad=3, w_pad=0, h_pad=0)
    # Shrink current axis by 20%
    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.95, box.height])

    # Put a legend to the right of the current axis
    ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    plt.savefig("experiment/nf-plot_pr-ts-"+str(selectionSequenceId)+".svg")


def visualize_pr_timestamps_granular(filename1, filename2, granularity):
    def process_file(filename):
        packet_timestamps = []
        with open(filename) as f:
            for line in f:
                packet_timestamps.append(int(float(line[1:].strip())))

        packet_timestamps_sec = [ts * 1e-9 for ts in packet_timestamps]
        return packet_timestamps_sec

    def calculate_packet_rate(packet_timestamps_sec, granularity):
        min_time, max_time = min(packet_timestamps_sec), max(
            packet_timestamps_sec)
        bins = int((max_time - min_time) // granularity + 1)
        packet_rate = [0] * bins

        for ts in packet_timestamps_sec:
            idx = int((ts - min_time) // granularity)
            packet_rate[idx] += 1

        packet_rate_per_second = [
            rate / granularity for rate in packet_rate][:-1]
        return packet_rate_per_second

    packet_timestamps_sec1 = process_file(filename1)
    if filename2:
        packet_timestamps_sec2 = process_file(filename2)

    packet_rate_per_second1 = calculate_packet_rate(
        packet_timestamps_sec1, granularity)
    if filename2:
        packet_rate_per_second2 = calculate_packet_rate(packet_timestamps_sec2, granularity)

    bins = len(packet_rate_per_second1)
    x_axis = [i * granularity for i in range(bins)]

    fig, ax = plt.subplots(figsize=(11, 8))
    my_fontsize = 14.5
    plt.rcParams.update({'font.size': my_fontsize})

   
    if filename2:
        l1, = ax.plot(x_axis, packet_rate_per_second1, color = 'tab:orange')
        l2, = ax.plot(x_axis, packet_rate_per_second2, color = 'tab:blue')
    else:
        l1, = ax.plot(x_axis, packet_rate_per_second1, color = 'tab:blue')

    ax.grid()
    ax.set_ylim(0,60)
    ax.set_xlim(0,60)
    ax.tick_params(axis='both', which='major', labelsize=my_fontsize-1)
    if filename2:
        ax.legend(handles = [l1,l2], labels = [
            f'Camera 1',
            f'Camera 2',
        ], loc='upper center', bbox_to_anchor=(0.5, -0.12), ncol=2)
    else:
        ax.legend(handles = [l1], labels = [
            f'Camera 1',
        ], loc='upper center', bbox_to_anchor=(0.5, -0.12), ncol=1)

    plt.xlabel('Time (s)', fontsize = my_fontsize)
    plt.ylabel('Packet Rate (pps)', fontsize = my_fontsize)
    plt.tight_layout()
    fig.subplots_adjust(bottom=0.17)
    fig.canvas.manager.set_window_title('Dual Observed and Filtered Packets - Timestamps')
    
    plt.savefig("experiment/nf-plot_pr-timestamp.svg")


def visualize_pr_dual(data_filename1, data_filename2, background=False):

    def mean_error_deviation(data):
        mean = np.mean(data)
        deviations = np.abs(np.array(data) - mean)
        return np.mean(deviations)

    def read_data_file(filename):
        filtered_packets = []
        parsed_packets = []
        times = []
        alternate_times = True
        with open(filename) as f:
            for line in f:
                if len(line) > 0:
                    parts = line.split(':')
                    if parts[0].startswith('f'):
                        filtered_packets.append(float(parts[1]))
                    else:
                        parsed_packets.append(float(parts[1]))
                    if alternate_times:
                        times.append(float(parts[0][1:]))
                    alternate_times = not alternate_times
        return filtered_packets, parsed_packets, times

    filtered_packets1, parsed_packets1, times1 = read_data_file(data_filename1)
    filtered_packets2, parsed_packets2, times2 = read_data_file(data_filename2)

    # Function to remove inactive time in the beginning and end
    def remove_inactive_time(filtered_packets, parsed_packets, times):
        for _ in range(2):
            filtered_packets.reverse()
            parsed_packets.reverse()
            times.reverse()
            i = 0
            while len(filtered_packets) > i and filtered_packets[i] == 0.0 and parsed_packets[i] == 0.0:
                i += 1
            i += 1
            filtered_packets = filtered_packets[i:]
            parsed_packets = parsed_packets[i:]
            times = times[i:]
        return filtered_packets, parsed_packets, times

    filtered_packets1, parsed_packets1, times1 = remove_inactive_time(
        filtered_packets1, parsed_packets1, times1)
    filtered_packets2, parsed_packets2, times2 = remove_inactive_time(
        filtered_packets2, parsed_packets2, times2)

    # Convert time to relative time
    def convert_relative_time(times):
        for i in range(len(times) - 1):
            times[i+1] -= times[0]
        times[0] = 0
        return times

    times1 = convert_relative_time(times1)
    times2 = convert_relative_time(times2)

    # Remove the last element
    def remove_last_element(arr):
        return arr[:-1]

    times1 = remove_last_element(times1)
    parsed_packets1 = remove_last_element(parsed_packets1)
    filtered_packets1 = remove_last_element(filtered_packets1)
    times2 = remove_last_element(times2)
    parsed_packets2 = remove_last_element(parsed_packets2)
    filtered_packets2 = remove_last_element(filtered_packets2)

    # Calculate mean error deviations
    mean_error_deviation1 = mean_error_deviation(filtered_packets1)
    mean_error_deviation2 = mean_error_deviation(filtered_packets2)

   

    # cut the source data to prepare for interpolation (otherwise extrapolation would be required)
    while times1[0] < times2[0]:
        times1 = times1[1:]
        filtered_packets1 = filtered_packets1[1:]
        parsed_packets1 = parsed_packets1[1:]

    while times1[-1] > times2[-1]:
        times1 = times1[:-1]
        filtered_packets1 = filtered_packets1[:-1]
        parsed_packets1 = parsed_packets1[:-1]

    # # Resample the parsed_packets arrays
    # f1 = interp1d(times1, filtered_packets1)
    # f2 = interp1d(times2, filtered_packets2)
    # # Define the common set of measurement points

    # filtered_packets1 = f1(times1)
    # filtered_packets2 = f2(times2)

    # Compute the differences
    # background_packets = parsed_packets1 - filtered_packets1 - filtered_packets2

    fig, ax = plt.subplots(figsize=(11, 8))
    my_fontsize = 14.5
    plt.rcParams.update({'font.size': my_fontsize})

    l1, = ax.plot(times1, filtered_packets1, color = 'tab:orange')
    l2 = ax.axhline(np.mean(filtered_packets1), color='orange',
               linestyle='dashed')

    l3, = ax.plot(times2, filtered_packets2, color = "tab:blue")
    l4 = ax.axhline(np.mean(filtered_packets2), color='blue',
               linestyle='dashed')

    # if background:
    #     ax.plot(times1, background_packets, label="Background Traffic")

    ax.grid()
    ax.set_ylim(ymin=0)
    ax.set_xlim(0,60)
    ax.tick_params(axis='both', which='major', labelsize=my_fontsize-1)
    ax.legend(handles = [l1,l2,l3,l4], labels = [
        f'Camera 1 - mean error deviation: {mean_error_deviation1:.2f} pps',
        f'Camera 1 - average: {np.mean(filtered_packets1):.2f} pps',
        f'Camera 2 - mean error deviation: {mean_error_deviation2:.2f} pps',
        f'Camera 2 - average: {np.mean(filtered_packets2):.2f} pps',
    ], loc='upper center', bbox_to_anchor=(0.5, -0.12), ncol=1)

    plt.xlabel('Time (s)', fontsize = my_fontsize)
    plt.ylabel('Packet Rate (pps)', fontsize = my_fontsize)
    plt.tight_layout()
    fig.subplots_adjust(bottom=0.28)
    fig.canvas.manager.set_window_title('Dual Observed and Filtered Packets')

    plt.savefig("experiment/nf-plot_pr-dual.svg")


def visualize_pr_quad(data_filename1, data_filename2, data_filename3, data_filename4, background=False):

    def process_file(data_filename):
        filtered_packets = []
        parsed_packets = []
        times = []
        alternate_times = True
        with open(data_filename) as f:
            for line in f:
                if len(line) > 0:
                    parts = line.split(':')
                    if parts[0].startswith('f'):
                        filtered_packets.append(float(parts[1]))
                    else:
                        parsed_packets.append(float(parts[1]))
                    if alternate_times:
                        times.append(float(parts[0][1:]))
                    alternate_times = not alternate_times

        # Cut off inactive time and convert time to relative time
        for _ in range(2):
            filtered_packets.reverse()
            parsed_packets.reverse()
            times.reverse()
            i = 0
            while len(filtered_packets) > i and filtered_packets[i] == 0.0 and parsed_packets[i] == 0.0:
                i += 1
            i += 1
            filtered_packets = filtered_packets[i:]
            parsed_packets = parsed_packets[i:]
            times = times[i:]

        for i in range(len(times) - 1):
            times[i+1] -= times[0]
        times[0] = 0

        # Dirty cleanup at the end
        times = times[:-1]
        parsed_packets = parsed_packets[:-1]
        filtered_packets = filtered_packets[:-1]

        return times, filtered_packets, parsed_packets

    times1, filtered_packets1, parsed_packets1 = process_file(data_filename1)
    times2, filtered_packets2, parsed_packets2 = process_file(data_filename2)
    times3, filtered_packets3, parsed_packets3 = process_file(data_filename3)
    times4, filtered_packets4, parsed_packets4 = process_file(data_filename4)

    def mean_error_deviation(data):
        mean = np.mean(data)
        deviations = np.abs(np.array(data) - mean)
        return np.mean(deviations)

    # Calculate mean error deviations
    mean_error_deviation1 = mean_error_deviation(filtered_packets1)
    mean_error_deviation2 = mean_error_deviation(filtered_packets2)
    mean_error_deviation3 = mean_error_deviation(filtered_packets3)
    mean_error_deviation4 = mean_error_deviation(filtered_packets4)
    # Visualization
    fig, ax = plt.subplots(figsize=(11, 8))
    my_fontsize = 14.5
    plt.rcParams.update({'font.size': my_fontsize})

    l1, = ax.plot(times1, filtered_packets1, color = 'tab:orange')
    #  ax.axhline(np.mean(filtered_packets1), color='blue',
    #    linestyle='dashed', label='Filtered packets Cam 1 average')

    l2, = ax.plot(times2, filtered_packets2, color = 'tab:blue')
    # ax.axhline(np.mean(filtered_packets2), color='orange',
    # #    linestyle='dashed', label='Filtered packets Cam 2 average')


    l3, = ax.plot(times3, filtered_packets3, color = 'tab:red')
    # ax.axhline(np.mean(filtered_packets3), color='green',
    #    linestyle='dashed', label='Filtered packets Cam 3 average')

    l4, = ax.plot(times4, filtered_packets4, color = 'tab:green')
    # ax.axhline(np.mean(filtered_packets4), color='red',
    #    linestyle='dashed', label='Filtered packets Cam 4 average')
    
   

    ax.grid()
    ax.set_ylim(0,70)
    ax.set_xlim(0,60)
    ax.tick_params(axis='both', which='major', labelsize=my_fontsize-1)
    ax.legend(handles = [l1,l2,l3,l4], labels = [
        f'Camera 1 (no Packet Report export)\n(mean error deviation: {mean_error_deviation1:.2f})',
        f'Camera 2 (no Packet Report export)\n(mean error deviation: {mean_error_deviation2:.2f})',
        f'Camera 1 (incl. Packet Report export)\n(mean error deviation: {mean_error_deviation3:.2f})',
        f'Camera 2 (incl. Packet Report export)\n(mean error deviation: {mean_error_deviation4:.2f})',
    ], loc='upper center', bbox_to_anchor=(0.5, -0.12), ncol=2)
    
    fig.canvas.manager.set_window_title('Quad Filtered Packets')
    plt.xlabel('Time (s)', fontsize = my_fontsize)
    plt.ylabel('Packet Rate (pps)', fontsize = my_fontsize)
    plt.tight_layout()
    fig.subplots_adjust(bottom=0.28)

    plt.savefig("experiment/nf-plot_pr-quad.svg")


def visualize_iat(data_filename, selectionSequenceId):

    interarrival_times = []
    times = []
    numbers = []
    counter = 0
    with open(data_filename) as f:
        for line in f:
            if len(line) > 0:
                parts = line.split(':')
                interarrival_times.append(float(parts[1])/1000000)  # ns to ms
                times.append(float(parts[0][1:]))
                numbers.append(counter)
                counter += 1

    fig, ax = plt.subplots(figsize=(14, 10))
    # ax.plot(times, interarrival_times, label='Interarrival Times')
    # ax.plot(numbers, interarrival_times, '-o', label='Interarrival Times')
    ax.plot(numbers, interarrival_times, label='Interarrival Times')
    ax.axhline(np.mean(interarrival_times), color='blue',
               linestyle='dashed', label='Interarrival Time Average')
    ax.axhline(0, color="black")
    # ax.set_xlabel('Time (s)')
    ax.set_xlabel('Packet Number')
    ax.set_ylabel('Interarrival Time (ms)')
    ax.set_title("Interarrival Time (SelectionProcess: " +
                 str(selectionSequenceId)+")")
    fig.canvas.manager.set_window_title(
        'Interarrival Time '+str(selectionSequenceId))
    ax.set_ylim(ymin=0)
    ax.set_xlim(xmin=0)
    plt.tight_layout(pad=3, w_pad=0, h_pad=0)
    # Shrink current axis by 20%
    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])

    # Put a legend to the right of the current axis
    ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    plt.savefig("experiment/nf-plot_iat-"+str(selectionSequenceId)+".svg")


def visualize_iat_timebased(iat_filename, timestamps_filename, selectionSequenceId):

    interarrival_times = []
    times = [0]
    numbers = []
    counter = 0
    timestamps = open(timestamps_filename).readlines()
    with open(iat_filename) as f:
        for line in f:
            if len(line) > 0:
                parts = line.split(':')
                interarrival_times.append(float(parts[1])/1e6)  # ns to ms
                times.append(
                    (times[-1]+int(float(timestamps[counter][1:-1]))-int(float(timestamps[0][1:-1])))/1e9)
                numbers.append(counter)
                counter += 1

    times = times[1:]
    fig, ax = plt.subplots(figsize=(11, 5))
    my_fontsize = 14.5
    plt.rcParams.update({'font.size': my_fontsize})
    # ax.plot(times, interarrival_times, label='Interarrival Times')
    # ax.plot(numbers, interarrival_times, '-o', label='Interarrival Times')
    l1, = ax.plot(times, interarrival_times)
    # ax.axhline(np.mean(interarrival_times), color='blue',
    #            linestyle='dashed', label='Interarrival Times Average')
    # ax.axhline(0, color="black")
    # ax.set_xlabel('Time (s)')

    ax.grid()
    ax.set_ylim(0,35)
    ax.set_xlim(0,3)
    ax.tick_params(axis='both', which='major', labelsize=my_fontsize-1)
    ax.legend(handles = [l1], labels = [
        f'Camera 1',
    ], loc='upper center', bbox_to_anchor=(0.5, -0.17), ncol=1)


    plt.xlabel('Time (s)', fontsize = my_fontsize)
    plt.ylabel('Interarrival Time (ms)', fontsize = my_fontsize)
    plt.tight_layout()
    fig.subplots_adjust(bottom=0.24)
    fig.canvas.manager.set_window_title(
        'Interarrival Time time-based'+str(selectionSequenceId))

    plt.savefig("experiment/nf-plot_iat-t-" +
                str(selectionSequenceId) + ".svg")


def visualize_iat_timebased_dual(iat_filename1, timestamps_filename1, iat_filename2, timestamps_filename2, selectionSequenceIds):

    interarrival_times1 = []
    times1 = [0]
    numbers1 = []
    counter1 = 0
    timestamps1 = open(timestamps_filename1).readlines()
    with open(iat_filename1) as f:
        for line in f:
            if len(line) > 0:
                parts = line.split(':')
                interarrival_times1.append(float(parts[1])/1e6)  # ns to ms
                times1.append(
                    (times1[-1]+int(timestamps1[counter1][1:-1])-int(timestamps1[0][1:-1]))/1e9)
                numbers1.append(counter1)
                counter1 += 1

    times1 = times1[1:]

    interarrival_times2 = []
    times2 = [0]
    numbers2 = []
    counter2 = 0
    timestamps2 = open(timestamps_filename2).readlines()
    with open(iat_filename2) as f:
        for line in f:
            if len(line) > 0:
                parts = line.split(':')
                interarrival_times2.append(float(parts[1])/1e6)  # ns to ms
                times2.append(
                    (times2[-1]+int(timestamps2[counter2][1:-1])-int(timestamps2[0][1:-1]))/1e9)
                numbers2.append(counter2)
                counter2 += 1

    times2 = times2[1:]
    fig, ax = plt.subplots(figsize=(14, 10))
    # ax.plot(times, interarrival_times, label='Interarrival Times')
    # ax.plot(numbers, interarrival_times, '-o', label='Interarrival Times')
    ax.plot(times1, interarrival_times1, label='Cam 1')
    # ax.axhline(np.mean(interarrival_times1), color='blue',
    #    linestyle='dashed', label='Average Cam 1')
    ax.plot(times2, interarrival_times2, label='Cam 2')
    # ax.axhline(np.mean(interarrival_times2), color='orange',
    #    linestyle='dashed', label='Average Cam 2')
    # ax.axhline(0, color="black")
    ax.set_ylim(ymin=0)
    ax.set_xlim(xmin=0)
    plt.xlabel('Time (s)', fontsize=14)
    plt.ylabel('Interarrival Time (ms)', fontsize=14)

    # set font of all elements to size 22
    plt.rc('font', size=14)
    # ax.set_title("Interarrival Time Dual (SelectionProcess: " +
    #  str(selectionSequenceIds[0]) + " " + str(selectionSequenceIds[1]) + ")")
    ax.set_title("Interarrival Times per Cam")
    fig.canvas.manager.set_window_title(
        'Interarrival Time time-based'+str(selectionSequenceIds))
    plt.tight_layout(pad=3, w_pad=0, h_pad=0)
    # Shrink current axis by 10%
    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.9, box.height])

    # Put a legend to the right of the current axis
    ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))

    plt.savefig("experiment/nf-plot_iat_dual-t.svg")


def visualize_iat_pcap(filename):

    capture = pyshark.FileCapture(filename)

    previous_packet_time = None
    iats = []

    for packet in capture:
        # Get the time of the current packet
        current_packet_time = float(packet.sniff_time.timestamp())
        # print(current_packet_time)
        if previous_packet_time is not None:
            # Calculate the interarrival time between the previous and current packet
            iats += [(current_packet_time - previous_packet_time)*1000]
            # if iats[-1] < 0:
            #     print (iats[-10:])
        # Update the previous packet time to the current packet time
        previous_packet_time = current_packet_time
    capture.close()

    numbers = list(range(len(iats)))
    fig, ax = plt.subplots(figsize=(14, 10))
    # ax.plot(times, interarrival_times, label='Interarrival Times')
    ax.plot(numbers, iats, label='Interarrival Times')
    ax.axhline(np.mean(iats), color='blue',
               linestyle='dashed', label='Interarrival Time Average')
    # ax.set_xlabel('Time (s)')
    ax.set_xlabel('Packet Number')
    ax.set_ylabel('Interarrival Time (ms)')
    ax.set_title("Interarrival Time pcap")
    fig.canvas.manager.set_window_title('Interarrival Time pcap')
    ax.legend()
    plt.savefig("experiment/pcap-plot_iat.svg")


def visualize_pl(data_filename):

    packet_losses = []
    out_of_orders = []
    times = []

    id_count = 0
    with open(data_filename) as f:
        for line in f:
            if len(line) > 0:
                parts = line.split(':')
                time = float(parts[0])
                cur_id = int(parts[1])
                times.append(time)
                if id_count == 0:
                    id_count = cur_id
                    packet_losses.append(0)
                    out_of_orders.append(0)
                else:
                    if cur_id == id_count + 1:
                        # no packet loss occurred
                        packet_losses.append(0)
                        out_of_orders.append(0)
                        id_count += 1
                    elif cur_id > id_count:
                        # packet loss occurred
                        packet_losses.append(1)
                        out_of_orders.append(0)
                        id_count = cur_id
                    elif cur_id <= id_count:
                        # out of order
                        packet_losses.append(0)
                        out_of_orders.append(1)
                        id_count = cur_id

    fig, ax = plt.subplots(figsize=(20, 5))
    ax.plot(times, packet_losses, label='Packet Loss')
    ax.plot(times, out_of_orders, label='Out of Order')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Occurence')
    ax.set_title('Packet Loss and Out of Order Packets')
    fig.canvas.manager.set_window_title('Packet Loss and Out of Order Packets')
    ax.legend()
    plt.savefig("experiment/nf-plot_pl.svg")

def visualize_throughput(filename1, filename2, granularity):

    def process_file(filename):
        packet_timestamps = []
        packet_sizes = []
        with open(filename) as f:
            for line in f:
                parts = line.split(':')
                packet_timestamps.append(int(parts[0][1:].strip()))
                packet_sizes.append(int(parts[1].strip()))

        packet_timestamps_sec = [ts * 1e-9 for ts in packet_timestamps]
        return packet_timestamps_sec, packet_sizes

    def calculate_throughput(packet_timestamps_sec, packet_sizes, granularity):
        min_time, max_time = min(packet_timestamps_sec), max(packet_timestamps_sec)
        bins = int((max_time - min_time) // granularity + 1)
        throughput = [0] * bins

        for ts, size in zip(packet_timestamps_sec, packet_sizes):
            idx = int((ts - min_time) // granularity)
            throughput[idx] += size

        throughput_mbps = [rate * 8 / (granularity * 1e6) for rate in throughput][:-1]
        return throughput_mbps

    packet_timestamps_sec1, packet_sizes1 = process_file(filename1)
    # packet_timestamps_sec2, packet_sizes2 = process_file(filename2)

    throughput_mbps1 = calculate_throughput(packet_timestamps_sec1, packet_sizes1, granularity)
    # throughput_mbps2 = calculate_throughput(packet_timestamps_sec2, packet_sizes2, granularity)
    

    bins = len(throughput_mbps1)
    x_axis = [i * granularity for i in range(bins)[:-1]]
    throughput_mbps1=throughput_mbps1[:-1]

    fig, ax = plt.subplots(figsize=(11, 5))
    my_fontsize = 14.5
    plt.rcParams.update({'font.size': my_fontsize})

    l1, = ax.plot(x_axis, throughput_mbps1, label="Cam 1")
    # ax.axhline(np.mean(throughput_mbps1), color='blue'),
    #    linestyle='dashed', label='Average Cam 1')
    # ax.plot(x_axis, throughput_mbps2, label="File 2")

    ax.grid()
    # ax.set_ylim(ymin=0)
    ax.set_xlim(0,60)
    ax.tick_params(axis='both', which='major', labelsize=my_fontsize-1)
    ax.legend(handles = [l1], labels = [
        f'Camera 1',
    ], loc='upper center', bbox_to_anchor=(0.5, -0.17), ncol=1)

    plt.xlabel('Time (s)', fontsize = my_fontsize)
    plt.ylabel('Throughput (Mbit/s)', fontsize = my_fontsize)
    plt.tight_layout()
    fig.subplots_adjust(bottom=0.24)

    plt.savefig("experiment/nf-plot_throughput" + ".svg")


def linear_function():
    # Define the x and y axis data
    x = np.linspace(0, 60, 100)
    y = (10/60) * x
    
    fig, ax = plt.subplots(figsize=(11, 8))
    my_fontsize = 14.5
    plt.rcParams.update({'font.size': my_fontsize})

    l1, = ax.plot(x, y, color = 'tab:blue')

    ax.grid()
    ax.set_ylim(0,10)
    ax.set_xlim(0,60)
    ax.tick_params(axis='both', which='major', labelsize=my_fontsize-1)
    ax.legend(handles = [l1], labels = [
        f'Camera 1, Camera 2',
    ], loc='upper center', bbox_to_anchor=(0.5, -0.12), ncol=1)

    plt.xlabel('Time (s)', fontsize = my_fontsize)
    plt.ylabel('Packet Loss (%)', fontsize = my_fontsize)
    plt.tight_layout()
    fig.subplots_adjust(bottom=0.18)
    fig.canvas.manager.set_window_title('Linear Function')

    plt.savefig("experiment/linear-function.svg")


# Start Visualizations
VIS = True
if VIS:
    selectionSequenceIds = [16777218, 16777217]
    linear_function()
    # selectionSequenceIds = selectionSequenceIds[:1]
    # selectionSequenceIds = [37]
    # for sId in selectionSequenceIds:
        # visualize_pr_timestamps("experiment/nf-data_timestamp-" +
        #  str(sId) + ".txt", sId)
    #     # visualize_pr("experiment/nf-data_pr-" +
    #     #              str(sId) + ".txt", sId)

    #     # visualize_iat("experiment/nf-data_iat-" + str(sId) + ".txt", sId)

    # visualize_pr_timestamps_granular(
    #     "experiment/nf-data_timestamp-" + str(selectionSequenceIds[1]) + ".txt",
    #     "", 0.2)
    # visualize_iat_timebased("experiment/nf-data_iat-" + str(selectionSequenceIds[0]) + ".txt", "experiment/nf-data_timestamp-" +
                                # str(selectionSequenceIds[0]) + ".txt", selectionSequenceIds[0])
    # visualize_throughput("experiment/nf-data_throughput-" + str(selectionSequenceIds[0]) + ".txt","", 0.2)
    # selectionSequenceIds.reverse()
    # visualize_pr_dual("experiment/nf-data_pr-" + str(
    #     selectionSequenceIds[0]) + ".txt", "experiment/nf-data_pr-" + str(selectionSequenceIds[1]) + ".txt")
    # visualize_pr_timestamps_granular(
    #     "experiment/nf-data_timestamp-" + str(selectionSequenceIds[0]) + ".txt",
    #     "experiment/nf-data_timestamp-" + str(selectionSequenceIds[1]) + ".txt", 0.2)
    # Call the function with the file containing packet timestamps

    # visualize_iat_timebased_dual("experiment/nf-data_iat-" + str(selectionSequenceIds[0]) + ".txt", "experiment/nf-data_timestamp-" +
    #                              str(selectionSequenceIds[0]) + ".txt", "experiment/nf-data_iat-" + str(selectionSequenceIds[1]) + ".txt", "experiment/nf-data_timestamp-" +
    #                              str(selectionSequenceIds[1]) + ".txt", selectionSequenceIds)
    visualize_pr_quad("/home/tristan/Documents/test/ba-doering/prototype/experiments/experiment_data/camonly_dual/running with only report interpretation export/run1-0.2/nf-data_pr-16777218.txt",
                      "/home/tristan/Documents/test/ba-doering/prototype/experiments/experiment_data/camonly_dual/running with only report interpretation export/run1-0.2/nf-data_pr-16777217.txt",
                      "/home/tristan/Documents/test/ba-doering/prototype/experiments/experiment_data/camonly_dual/running with packet report export in the background/run1-0.2exportrate/nf-data_pr-16777218.txt",
                      "/home/tristan/Documents/test/ba-doering/prototype/experiments/experiment_data/camonly_dual/running with packet report export in the background/run1-0.2exportrate/nf-data_pr-16777217.txt")
    # visualize_iat_pcap("pcaps/camonly_dual_adu-jitter.pcap")
    plt.show()
    # visualize_pl("nf-data_pl-" + str(selectionSequenceId) +".txt")
