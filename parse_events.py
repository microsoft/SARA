# coding=utf8

"""
Parse events
"""
import json
import codecs
import re, os
import argparse
import events_to_actions 
from pprint import pprint
from interactions.util import extract_info
from interactions import event
from interactions import touch as touch_processor
from interactions import key as key_processor
from interactions import webview_key as wv_key_processor
from interactions import input as input_processor
from interactions import popup_window as popup_window_processor
from interactions import low_level_sensor as low_level_sensor_processor
from interactions import location as location_processor
from interactions import webview_page_loaded as wv_page_loaded_processor


ACTIVITY_TAG = '[Activity]'
DIALOG_TAG = '[Dialog]'
POPUPWINDOW_TAG = '[PopupWindow]'
VIEW_TAG = '[ViewOnTouchEvent]'
EDITABLE_INPUT_CONNECTION_TAG = '[EditableInputConnection]'
SPANNER_STRING_BUILDER_TAG = '[SpannerStringBuilder]'
TEXT_VIEW_KEY_TAG = '[TextViewKeyboard]'
WEBVIEW_CONSOLE_TAG = '[WebViewConsole]'
WEBVIEW_KEY_EVENT_TAG = '[WebViewKeyEvent]'
WEBVIEW_CLIENT_TAG = '[WebViewClient]'
SENSOR_LISTENER_TAG = '[SensorListener]'
LOCATION_LISTENER_TAG = '[LocationListener]'
LOCATION_MANAGER_TAG = '[LocationManager]'

ACTIVITY_PATTERN = re.compile(r'^\[Activity\](.*)')
DIALOG_PATTERN = re.compile(r'^\[Dialog\](.*)')
POPUP_WINDOW_PATTERN = re.compile(r'^\[PopupWindow\](.*)')
VIEW_PATTERN = re.compile(r'^\[ViewOnTouchEvent\](.*)')
EDITABLE_INPUT_CONNECTION_PATTERN = re.compile(r'^\[EditableInputConnection\](.*)')
SPANNER_STRING_BUILDER_PATTERN = re.compile(r'^\[SpannerStringBuilder\](.*)')
TEXT_VIEW_KEY_PATTERN = re.compile(r'^\[TextViewKeyboard\](.*)')
WEBVIEW_CONSOLE_PATTERN = re.compile(r'^\[WebViewConsole\](.*)')
WEBVIEW_CLIENT_PATTERN = re.compile(r'^\[WebViewClient\](.*)')
LOCATION_MANAGER_PATTERN = re.compile(r'^\[LocationManager\](.*)')
LOCATION_LISTENER_PATTERN = re.compile(r'^\[LocationListener\](.*)')
SENSOR_LISTENER_PATTERN = re.compile(r'^\[SensorListener\](.*)')


def compare_logs(log_1, log_2):
    log_1_info, log_2_info = extract_info(log_1), extract_info(log_2)

    keys = ['tag', 'plid', 'package']
    for k in keys:
        if log_1_info[k] != log_2_info[k]:
            return False

    if len(log_1_info['content']) != len(log_2_info['content']):
        return False

    keys = list(log_1_info['content'].keys())
    for k in keys:
        if k == 'target' or k == 'webview':
            continue
        if log_1_info['content'][k] != log_2_info['content'][k]:
            return False
    return True


def find_match(log):
    """
    Filter log by tags
    """
    patterns = [
        ACTIVITY_PATTERN, 
        DIALOG_PATTERN, 
        POPUP_WINDOW_PATTERN, 
        VIEW_PATTERN, 
        EDITABLE_INPUT_CONNECTION_PATTERN,
        SPANNER_STRING_BUILDER_PATTERN,
        TEXT_VIEW_KEY_PATTERN,
        WEBVIEW_CONSOLE_PATTERN,
        WEBVIEW_CLIENT_PATTERN,
        LOCATION_MANAGER_PATTERN,
        LOCATION_LISTENER_PATTERN,
        SENSOR_LISTENER_PATTERN
    ]
    for pattern in patterns:
        if pattern.match(log):
            return True
    return False


def save_file(file_name, suffix, content):
    """
    Get the prefix of file, and its path
    """
    full_path = os.path.abspath(file_name)
    filename, file_extension = os.path.splitext(full_path)
    save_path = '_'.join([filename, suffix]) + file_extension
    with open(save_path, 'w') as f:
        f.write(content)
    return save_path


def preprocess(file):
    """
    1. Eliminate redundant log
    2. Eliminate irrelevant logs (Only reserve [Activity], [Dialog], [PopupWindow], [ViewOnTouchEvent], [EditableInputConnection], [SpannerStringBuilder], [TextViewKeyboard])
    """
    valid_logs = list()
    with open(file, 'r') as f:
        prev_log = None
        for log in f:
            log = log.strip()
            if not find_match(log):
                continue
            if VIEW_PATTERN.match(log):
                log_info = extract_info(log)
                if 'handle' in log_info['content']:
                    continue
            if prev_log is None:
                prev_log = log
                valid_logs.append(log)
            else:
                if LOCATION_LISTENER_PATTERN.match(log) or SENSOR_LISTENER_PATTERN.match(log):
                    valid_logs.append(log)
                    prev_log = log
                else:
                    if compare_logs(prev_log, log):
                        continue
                    valid_logs.append(log)
                    prev_log = log
    save_path = save_file(file, 'preprocess', '\n'.join(valid_logs))
    return save_path


def search_activity_group(log_info, logs, curr_idx):
    """
    <down_idx, up_idx>
    TouchEvent and KeyEvent may be missed in activity 
    """
    content = log_info['content']
    plid = log_info['plid']
    package = log_info['package']
    activity = content['activity']
    msg_type = content['msgType']

    search_target = None
    search_msg_type = None
    search_action_name = None
    search_action = None
    if msg_type.lower() == 'touchevent' and content['actionId'] == 0:
        # Touch down
        search_msg_type = msg_type
        search_action_name = 'actionId'
        search_action = 1
        search_target = activity
        down_time = content['downTime']
    if msg_type.lower() == 'keyevent' and content['actionCode'] == 0:
        # Key down
        search_msg_type = msg_type
        search_action_name = 'actionCode'
        search_action = 1
        search_target = activity
        down_time = content['downTime']

    if search_target is None:
        return None, curr_idx + 1

    # Search
    idx = curr_idx + 1
    return_idx = -1
    while idx < len(logs):
        _log_info = extract_info(logs[idx])
        _content = _log_info['content']
        idx += 1

        if _log_info['tag'] == ACTIVITY_TAG and _content['msgType'] == search_msg_type \
         and _content['activity'] == search_target and _content[search_action_name] == search_action and _content['downTime'] == down_time:
            if return_idx == -1:
                return_idx = idx
            return (curr_idx, idx-1, ACTIVITY_TAG, activity, search_msg_type), return_idx

        if _log_info['tag'] == POPUPWINDOW_TAG:
            return_idx = idx - 1

    return (curr_idx, curr_idx, ACTIVITY_TAG, activity, search_msg_type), curr_idx + 1


def search_dialog_group(log_info, logs, curr_idx):
    """
    <down_idx, up_idx>
    Auto complete dialog event since the event may fail to be logged when the dialog is destroying
    """
    content = log_info['content']
    dialog = content['dialog']
    msg_type = content['msgType']

    search_target = None
    search_msg_type = None
    search_action_name = None
    search_action = None
    if msg_type.lower() == 'touchevent' and content['actionId'] == 0:
        # Touch down
        search_msg_type = msg_type
        search_action_name = 'actionId'
        search_action = 1
        search_target = dialog
    if msg_type.lower() == 'keyevent' and content['actionCode'] == 0:
        # Key down
        search_msg_type = msg_type
        search_action_name = 'actionCode'
        search_action = 1
        search_target = dialog

    if search_target is None:
        return None, curr_idx + 1
    
    # Search
    idx = curr_idx + 1
    while idx < len(logs):
        _log_info = extract_info(logs[idx])
        _content = _log_info['content']
        idx += 1

        if _log_info['tag'] == DIALOG_TAG and _content['msgType'] == search_msg_type and _content['dialog'] == search_target and _content[search_action_name] == search_action:
            return (curr_idx, idx-1, DIALOG_TAG, dialog, search_msg_type), idx

    return (curr_idx, curr_idx, DIALOG_TAG, dialog, search_msg_type), curr_idx + 1


def search_popup_window_group(log_info, logs, curr_idx):
    content = log_info['content']
    popup_window = content['popupWindow']
    msg_type = content['msgType']

    popup_window_width = int(content['width'])
    popup_window_heigth = int(content['height'])

    if msg_type.lower() == 'action' and content['action'].lower() == 'show':
    # if msg_type.lower() == 'action' and content['action'].lower() == 'show' and (popup_window_width != -2 or popup_window_heigth != -2):
        idx = curr_idx + 1
        while idx < len(logs):
            _log_info = extract_info(logs[idx])
            _content = _log_info['content']
            idx += 1

            if _log_info['tag'] == POPUPWINDOW_TAG and _content['popupWindow'] == popup_window and _content['action'].lower() == 'hide':
                # search view
                v_idx = curr_idx + 1
                view_groups = list()
                while v_idx < idx - 1:

                    v_log_info = extract_info(logs[v_idx])

                    if v_log_info['tag'] == DIALOG_TAG:
                        group, next_v_idx = search_dialog_group(v_log_info, logs, v_idx)
                        if group is None:
                            v_idx += 1
                        else:
                            v_idx += 1
                            view_groups.append(group)
                    elif v_log_info['tag'] == VIEW_TAG:
                        group, next_v_idx = search_view_group(v_log_info, logs, v_idx)
                        if group is None:
                            v_idx += 1
                        else:
                            v_idx = next_v_idx
                            view_groups.append(group)
                    else:
                        v_idx += 1
                        continue

                return (curr_idx, idx-1, POPUPWINDOW_TAG, popup_window, view_groups, msg_type), idx

    return None, curr_idx + 1


def search_view_group(log_info, logs, curr_idx):
    content = log_info['content']
    msg_type = content['msgType'].lower()

    if msg_type == 'touchevent' and content['actionId'] == 0:
        view = content['view']
        down_time = content['downTime']
        idx = curr_idx + 1
        while idx < len(logs):
            _log_info = extract_info(logs[idx])
            _content = _log_info['content']
            idx += 1
            if _log_info['tag'] == VIEW_TAG and _content['msgType'].lower() == msg_type and _content['downTime'] == down_time and _content['actionId'] == 1:
                return (curr_idx, idx-1, VIEW_TAG, view, msg_type), idx

    return None, curr_idx + 1


def remove_invalid_groups(anchor, groups):
    new_groups = list()
    for group in groups:
        if anchor <= group[0]:
            break
        else:
            new_groups.append(group)
    return new_groups


def search_editable_input_connection_group(log_info, logs, curr_idx):
    content = log_info['content']
    editable_input_connection = content['editableInputConnection']
    msg_type = content['msgType']

    nested_group = list()

    if msg_type.lower() == 'type' and content['mBatchEditNesting'] != -1:
        idx = curr_idx + 1
        last_log_idx = curr_idx
        # Handle overlap EditableInputConnection
        first_overlap_idx = None
        while idx < len(logs):
            _log_info = extract_info(logs[idx])
            _content = _log_info['content']
            idx += 1
            if _log_info['tag'] == EDITABLE_INPUT_CONNECTION_TAG:
                
                if _content['editableInputConnection'] == editable_input_connection:
                    last_log_idx = idx - 1
                    if _content['mBatchEditNesting'] == -1:
                        if len(nested_group) > 0:
                            nested_group = remove_invalid_groups(last_log_idx, nested_group)
                        return (curr_idx, last_log_idx, EDITABLE_INPUT_CONNECTION_TAG, editable_input_connection, nested_group, msg_type), idx
                else:
                    if first_overlap_idx is None:
                        first_overlap_idx = idx - 1
                    else:
                        first_overlap_log_info = extract_info(logs[first_overlap_idx])
                        if first_overlap_log_info['content']['editableInputConnection'] != _content['editableInputConnection']:
                            # Second overlap, then dump
                            if len(nested_group) > 0:
                                nested_group = remove_invalid_groups(last_log_idx, nested_group)
                            return_idx = min(first_overlap_idx, last_log_idx) + 1
                            return (curr_idx, last_log_idx, EDITABLE_INPUT_CONNECTION_TAG, editable_input_connection, nested_group, msg_type), return_idx

            #  Support nested interaction with activity and dialog
            if _log_info['tag'] == ACTIVITY_TAG:
                group, _ = search_activity_group(_log_info, logs, idx-1)
                if group is not None:
                    nested_group.append(group)
            elif _log_info['tag'] == DIALOG_TAG:
                group, _ = search_dialog_group(_log_info, logs, idx-1)
                if group is not None:
                    nested_group.append(group)
            elif _log_info['tag'] == TEXT_VIEW_KEY_TAG:
                group, _ = search_textview_keyboard_group(_log_info, logs, idx-1)
                if group is not None:
                    nested_group.append(group)
            elif _log_info['tag'] == POPUPWINDOW_TAG:
                group, _ = search_popup_window_group(_log_info, logs, idx-1)
                if group is not None:
                    nested_group.append(group)

        if last_log_idx != curr_idx:
            if len(nested_group) > 0:
                nested_group = remove_invalid_groups(last_log_idx, nested_group)
            return_idx = last_log_idx + 1 if first_overlap_idx is None or (last_log_idx < first_overlap_idx) else first_overlap_idx + 1
            return (curr_idx, last_log_idx, EDITABLE_INPUT_CONNECTION_TAG, editable_input_connection, nested_group, msg_type), return_idx

    return None, curr_idx + 1


def search_textview_keyboard_group(log_info, logs, curr_idx):
    content = log_info['content']
    msg_type = content['msgType'].lower()
    textview_id = content['viewId']

    if msg_type == 'keyevent' and content['actionCode'] == 0:
        down_time = content['downTime']
        idx = curr_idx + 1
        while idx < len(logs):
            _log_info = extract_info(logs[idx])
            _content = _log_info['content']
            idx += 1
            if _log_info['tag'] == TEXT_VIEW_KEY_TAG and _content['msgType'].lower() == msg_type and _content['downTime'] == down_time and _content['actionCode'] == 1:
                return (curr_idx, idx-1, TEXT_VIEW_KEY_TAG, textview_id, msg_type), curr_idx+1

    return None, curr_idx + 1


def search_webview_console_group(log_info, logs, curr_idx):
    content = json.loads(log_info['content']['message'].split('[Frida]-')[1])
    msg_type = content['msgType'].lower()
    target = content['webview']

    if msg_type == 'webViewKeyEvent':
        return (curr_idx, curr_idx, WEBVIEW_KEY_EVENT_TAG, target, msg_type), curr_idx+1

    return None, curr_idx + 1


def search_webview_client_group(log_info, logs, curr_idx):
    content = log_info['content']
    msg_type = content['msgType'].lower()
    target = content['webview']

    if msg_type == 'webviewpageloaded':
        return (curr_idx, curr_idx, WEBVIEW_CLIENT_TAG, target, msg_type), curr_idx + 1

    return None, curr_idx + 1


def search_sensor_listener_group(log_info, logs, curr_idx):
    """
    low level sensor
    """
    content = log_info['content']
    msg_type = content['msgType'].lower()
    target = content['target']

    if msg_type == 'sensorevent':
        return (curr_idx, curr_idx, SENSOR_LISTENER_TAG, target, msg_type), curr_idx + 1

    return None, curr_idx + 1


def search_location_manager_group(log_info, logs, curr_idx):
    """
    getLastKnownLocation
    """
    content = log_info['content']
    msg_type = content['msgType'].lower()
    target = content['target']

    if msg_type == 'lastknownlocation':
        return (curr_idx, curr_idx, LOCATION_MANAGER_TAG, target, msg_type), curr_idx + 1

    return None, curr_idx + 1


def search_location_listener_group(log_info, logs, curr_idx):
    """
    onLocationChanged
    """
    content = log_info['content']
    msg_type = content['msgType'].lower()
    target = content['target']

    if msg_type == 'locationevent':
        return (curr_idx, curr_idx, LOCATION_LISTENER_TAG, target, msg_type), curr_idx + 1

    return None, curr_idx + 1


def group_logs(file):
    """
    1. Activity:
        a. touch:  DOWN -> UP
        b. key:    DOWN -> UP
    2. Dialog:
        a. touch:  DOWN -> UP
        b. key:    DOWN -> UP
    3. PopupWindow:
        a. action: show -> hide
    4. View:
        a. touch:  DOWN -> UP
    5. SpannerStringBuilder
        a. text
    6. EditableInputConnection:
        a. show: first-appear, last-appear
    7. WebViewConsole
    8. WebViewClient
    """
    logs = list()
    with open(file, 'r') as f:
        logs = f.readlines()

    func_dict = {
        ACTIVITY_TAG: search_activity_group,
        DIALOG_TAG: search_dialog_group,
        POPUPWINDOW_TAG: search_popup_window_group,
        EDITABLE_INPUT_CONNECTION_TAG: search_editable_input_connection_group,
        TEXT_VIEW_KEY_TAG: search_textview_keyboard_group,
        WEBVIEW_CONSOLE_TAG: search_webview_console_group,
        WEBVIEW_CLIENT_TAG: search_webview_client_group,
        SENSOR_LISTENER_TAG: search_sensor_listener_group,
        LOCATION_MANAGER_TAG: search_location_manager_group,
        LOCATION_LISTENER_TAG: search_location_listener_group
    }
    logs_length = len(logs)
    idx = 0
    groups = list()
    while idx < logs_length:
        log_info = extract_info(logs[idx])
        tag = log_info['tag']
        if tag in func_dict:
            group_info, next_idx = func_dict[tag](log_info, logs, idx)
            idx = next_idx
            if group_info is None:
                continue
            groups.append(group_info)
        else:
            idx += 1
    pprint(groups)
    save_path = save_file(file, 'groups', '\n'.join([str(g) for g in groups]))
    return save_path, groups, logs


def clear_logs(logs, target_tags):
    valid_logs = list()
    for log in logs:
        lf = extract_info(log)
        if lf['tag'] in target_tags:
            valid_logs.append(log)
    return valid_logs


def process_groups(groups, logs):
    """
    Process each group
    (log_start_idx, log_end_idx, tag, target, msgType)
    """
    events = list()
    
    for group in groups:
        tag = group[2]
        target = group[3]
        msg_type = group[-1].lower()
        if tag == ACTIVITY_TAG or tag == DIALOG_TAG or tag == VIEW_TAG:

            if group[0] == group[1]:
                if msg_type == 'touchevent':
                    events.append(touch_processor.create_touch_event(msg_type, target, logs[group[0]], group[0], tag))
                elif msg_type == 'keyevent':
                    events.append(key_processor.create_key_event(msg_type, target, logs[group[0]], group[0]))
                continue

            # Activity & Dialig
            if msg_type == 'touchevent':
                event_logs = clear_logs(logs[group[0]:group[1]+1], [ACTIVITY_TAG, DIALOG_TAG, VIEW_TAG])
                ev = touch_processor.parse_touch_event(msg_type, target, event_logs, group[0], tag)
            elif msg_type == 'keyevent':
                event_logs = clear_logs(logs[group[0]:group[1]+1], [ACTIVITY_TAG, DIALOG_TAG])
                ev = key_processor.parse_key_event(msg_type, target, event_logs, group[0])
            events.append(ev)
        elif tag == POPUPWINDOW_TAG:
            # PopupWindow, process view onTouchEvent
            events.append(popup_window_processor.create_popup_window_event(msg_type, target, logs[group[0]], group[0]))
            view_groups = group[4]
            view_events = process_groups(view_groups, logs)
            if len(view_events) != 0:
                events += view_events
            events.append(popup_window_processor.create_popup_window_event(msg_type, target, logs[group[1]], group[1]))
        elif tag == EDITABLE_INPUT_CONNECTION_TAG:
            # Input Event
            nested_groups = group[4]
            # Process nested events
            nested_events = process_groups(nested_groups, logs)
            evs = input_processor.parse_input_event(msg_type, target, logs[group[0]:group[1]+1], nested_events, group[0])
            events += evs
        elif tag == TEXT_VIEW_KEY_TAG:
            # Keyboard event caught by TextView onKeyPreIme
            event_logs = clear_logs(logs[group[0]:group[1]+1], [TEXT_VIEW_KEY_TAG])
            ev = key_processor.parse_key_event(msg_type, target, event_logs, group[0])
            ev.intent = event.KeyEvent.HIDE_KEYBOARD_INTENT
            events.append(ev)
        elif tag == WEBVIEW_KEY_EVENT_TAG:
            # WebView KeyBoard event
            event_logs = logs[group[0]:group[1]+1]
            ev = wv_key_processor.parse_key_event(msg_type, target, event_logs, group[0])
            events.append(ev)
        elif tag == WEBVIEW_CLIENT_TAG:
            # WebView page loaded
            event_logs = logs[group[0]:group[1]+1]
            ev = wv_page_loaded_processor.parse_page_loaded(msg_type, target, event_logs, group[0])
            events.append(ev)
        elif tag == SENSOR_LISTENER_TAG:
            # Low level sensor
            event_logs = logs[group[0]:group[1]+1]
            ev = low_level_sensor_processor.parse_low_level_sensor_event(msg_type, target, event_logs, group[0])
            events.append(ev)
        elif tag == LOCATION_MANAGER_TAG or tag == LOCATION_LISTENER_TAG:
            event_logs = logs[group[0]:group[1]+1]
            ev = location_processor.parse_location_sensor_event(msg_type, target, event_logs, group[0])
            events.append(ev)

    return events


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--trace', help='trace files', required=True)
    args = parser.parse_args()

    trace_file = args.trace
    save_path = preprocess(trace_file)
    save_path, groups, logs = group_logs(save_path)
    events = process_groups(groups, logs)
    print('================== Parse Events ====================')
    print(len(events))
    pprint(events)

    print('================== Scripts ====================')
    replay_script, messages, sensor_events = events_to_actions.generate_script(events)
    print(replay_script)
    full_path = os.path.abspath(trace_file)
    filename, file_extension = os.path.splitext(full_path)
    # svae replay script
    save_path = '_'.join([filename, 'replay']) + '.py'
    with codecs.open(save_path, 'w', encoding='utf8') as f:
        f.write(replay_script)
    # save replay messages
    msg_save_path = '_'.join([filename, 'replay', 'messages'])  + '.log'
    with codecs.open(msg_save_path, 'w', encoding='utf8') as f:
        f.write(json.dumps(messages, indent=2))
    sensor_events_save_path = '_'.join([filename, 'replay_sensor_events']) + '.log'
    with codecs.open(sensor_events_save_path, 'w', encoding='utf8') as f:
        f.write(json.dumps(sensor_events, indent=2))