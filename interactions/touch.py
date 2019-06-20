# coding=utf8

import statistics
from . import util
from . import event
from pprint import pprint

MIN_SWIPE_DISTANCE_X = 50
MIN_SWIPE_DISTANCE_Y = 50
MIN_TS_INTERVAL = 0.5
DEFAULT_LONG_PRESS_TIMEOUT = 500


def get_view_type(tag):
    if tag == util.ACTIVITY_TAG:
        view_type = 'Activity'
    elif tag == util.DIALOG_TAG:
        view_type = 'Dialog'
    elif tag == util.POPUPWINDOW_TAG:
        view_type = 'PopupWindow'
    else:
        view_type = None
    return view_type


def create_touch_event(msg_type, target, log, log_begin_idx, tag):
    """
    Create a single tap event
    :params  msg_type
    :params  target
    :params  single log
    :return: an instance of event.TouchEvent
    """
    log_info = util.extract_info(log)
    plid, package = log_info['plid'], log_info['package']
    content = log_info['content']

    return event.TouchEvent(
        plid=plid,
        package=package,
        log_begin_idx=log_begin_idx,
        msg_type=msg_type,
        target=target,
        begin_ts=log_info['ts'],
        end_ts=log_info['ts'],
        tap_type=event.TouchEvent.SHORT_TAP,
        x=content['x'],
        y=content['y'],
        duration=100,
        view_type=get_view_type(tag)
    )


def find_max_distance(infos):
    begin_x = infos[0]['x']
    begin_y = infos[0]['y']
    xlist = [info['x'] for info in infos]
    ylist = [info['y'] for info in infos]
    idx = 1
    max_distance_x = 0
    max_distance_y = 0
    while idx < len(xlist):
        cur_distance_x = abs(xlist[idx] - begin_x)
        cur_distance_y = abs(ylist[idx] - begin_y)
        max_distance_x = max(max_distance_x, cur_distance_x)
        max_distance_y = max(max_distance_y, cur_distance_y)
        idx += 1
    return max_distance_x, max_distance_y


def parse_touch_event(msg_type, target, logs, log_begin_idx, tag):
    """
    Parse touch event logs into interaction Gesture
    1. Tap
    2. LongTap
    3. Swipe
    :params  msg_type
    :params  target
    :params  logs [Pair of (Down, Up)]
    :return: an instance of event.TouchEvent
    """

    assert len(logs) >= 2

    log_info = [util.extract_info(log) for log in logs]
    plid, package = log_info[0]['plid'], log_info[0]['package']
    contents = [log['content'] for log in log_info]

    begin_x = contents[0]['x']
    begin_y = contents[0]['y']
    begin_ts = log_info[0]['ts']
    end_ts = log_info[-1]['ts']

    action_seqs = [con['action'] for con in contents if 'action' in con]
    next_action = contents[1]['action']
    if 'ACTION_MOVE' not in action_seqs:
        # Distinguish between Tap and LongTap
        begin_evtime = float(contents[0]['eventTime'])
        end_evtime = float(contents[-1]['eventTime'])
        evtime_interval = end_evtime - begin_evtime
        print('Interval: ', evtime_interval)
        if evtime_interval < DEFAULT_LONG_PRESS_TIMEOUT:
            action = event.TouchEvent.SHORT_TAP
        else:
            action = event.TouchEvent.LONG_TAP

        return event.TouchEvent(
            plid=plid,
            package=package,
            log_begin_idx=log_begin_idx,
            msg_type=msg_type,
            target=target,
            begin_ts=begin_ts,
            end_ts=end_ts,
            tap_type=action,
            x=begin_x,
            y=begin_y,
            duration=evtime_interval,
            view_type=get_view_type(tag)
        )

    else: 
        # next_action == 'ACTION_MOVE' and contents[-1]['action'] == 'ACTION_UP':
        # Swipe
        end_x = contents[-1]['x']
        end_y = contents[-1]['y']
        distance_x = end_x - begin_x
        distance_y = end_y - begin_y
        begin_evtime = float(contents[0]['eventTime'])
        next_evtime = float(contents[1]['eventTime'])
        evtime_interval = next_evtime - begin_evtime

        max_distance_x, max_distance_y = find_max_distance(contents)

        print(max_distance_x, max_distance_y)
        if max_distance_x > MIN_SWIPE_DISTANCE_X or max_distance_y > MIN_SWIPE_DISTANCE_Y:
            # Valid Swipe Action
            
            # Process Muiti-direction Movements
            idx = 1
            turning_points = list([0])
            while idx < len(logs)-1:
                delta_x = int(contents[idx+1]['x'] - contents[idx]['x'])
                delta_y = int(contents[idx+1]['y'] - contents[idx]['y'])
                if delta_x * distance_x < 0 or delta_y * distance_y < 0:
                    turning_points.append(idx)
                    distance_x = delta_x
                    distance_y = delta_y
                idx += 1
            pprint(turning_points)

            prev_ts = None
            intervals = list()
            pointers = list()
            for lf in log_info:
                pointers.append((max(lf['content']['x'], 0), max(lf['content']['y'],0)))
                if prev_ts is None:
                    prev_ts = float(lf['content']['eventTime'])
                else:
                    curr_ts = float(lf['content']['eventTime'])
                    interval = curr_ts - prev_ts
                    intervals.append(interval)
                    prev_ts = curr_ts

            # delete duplicate & adjacent points
            for i in range(len(pointers)-1, 0, -1):
                if pointers[i] == pointers[i-1]:
                    del pointers[i]

            action = event.SwipeEvent.SWIPE

            if evtime_interval > DEFAULT_LONG_PRESS_TIMEOUT:
                action = event.SwipeEvent.DRAG

            return event.SwipeEvent(
                    plid=plid,
                    package=package,
                    log_begin_idx=log_begin_idx,
                    msg_type=msg_type,
                    target=target,
                    begin_ts=begin_ts,
                    end_ts=end_ts,
                    motion_type=action,
                    from_x=begin_x,
                    from_y=begin_y,
                    to_x=end_x,
                    to_y=end_y,
                    pointers=pointers,
                    time_interval=statistics.median(intervals) / 1000
                )

        else:
            begin_evtime = float(contents[0]['eventTime'])
            next_evtime = float(contents[-1]['eventTime'])
            evtime_interval = next_evtime - begin_evtime
            tap_type = event.TouchEvent.LONG_TAP if evtime_interval > DEFAULT_LONG_PRESS_TIMEOUT else event.TouchEvent.SHORT_TAP
            return event.TouchEvent(
                    plid=plid,
                    package=package,
                    log_begin_idx=log_begin_idx,
                    msg_type=msg_type,
                    target=target,
                    begin_ts=begin_ts,
                    end_ts=end_ts,
                    tap_type=tap_type,
                    x=begin_x,
                    y=begin_y,
                    duration=evtime_interval,
                    view_type=get_view_type(tag)
                )
