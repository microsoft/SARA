# coding=utf8

import json
from pprint import pprint
from interactions import event
from script import util


def init_script():
    code = """# coding=utf8

import os
import sys
import time
import json
import frida
import argparse
import traceback
import uiautomator2 as u2
from script import util

sessions = None
xml = None
view_hierarchy = None
save_path = None
trace_fd = None
action_count = 0
current_popup_window = None
curr_webview_address = None

is_samsung = False

d = u2.connect()
print(d.info)


def log(desc, is_action=True):
    global action_count
    if is_action:
        log_str = '[ReplayAction]-%d: %s' % (action_count, desc)
    else:
        log_str = desc
    trace_fd.write(log_str + '\\n')
    print(log_str)


def error_handler(func):
    def wrapper(message, data):
        if message['type'] == 'error':
            print('[Func]: %s, [Error-msg]: %s' % (func.__name__, message))
            print('[Func]: %s, [Error-des]: %s' % (func.__name__, message['description']))
            print('[Func]: %s, [Error-sta]: %s' % (func.__name__, message['stack']))
            print('[Func]: %s, [Error-dat]: %s' % (func.__name__, data))
            return None
        else:
            return func(message, data)
    return wrapper


def preprocess_path():
    global save_path
    if save_path is None:
        return False
    if not os.path.exists(save_path):
        os.mkdir(save_path)
    else:
        for file in os.listdir(save_path):
            os.remove(os.path.join(save_path, file))
    return True


def post_action(custom_interval):
    global xml
    global d
    global action_count
    global save_path
    global view_hierarchy

    log('[ReplayTimeInterval]-%d: %s' % (action_count, json.dumps({'interval': custom_interval})), is_action=False)
    if action_count > 0:
        # time.sleep(1)
        if custom_interval > 0:
            time.sleep(custom_interval)
    xml = d.dump_hierarchy()
    xml = util.parse_xml(xml)
    screenshot_filename = os.path.join(save_path, '_'.join(['screenshot', str(action_count)]) + '.jpg')
    xml_filename = os.path.join(save_path, '_'.join(['ui', str(action_count)]) + '.xml')
    view_hierarchy_filename = os.path.join(save_path, '_'.join(['view_hierarchy', str(action_count)]) + '.xml')
    d.screenshot(screenshot_filename)
    util.save_xml(xml, xml_filename)
    view_hierarchy, lxml_view_hierarchy = util.dump_view_hierarchy(d, view_hierarchy_filename)
    action_count += 1


def set_text(plid, package, rid, bounds, text):
    global xml
    view = util.find_view(rid, bounds, xml)
    if view is None:
        print('TextView ' + rid + ' does not exist')
        focused = d(focused=True)
        if focused.count > 0:
            d(focused=True).set_text(text)
        else:
            d.shell('input text "%s"' % text)
        log('[set_text]-%s' % json.dumps({'rid': rid, 'text': text, 'bounds': bounds, 'plid': plid, 'package': package}))
    else:
        if len(rid) > 0:
            d(resourceId=rid, focused=True).set_text(text)
        else:
            d(focused=True).set_text(text)
        log('[set_text]-%s' % json.dumps({'rid': rid, 'text': text, 'bounds': bounds, 'plid': plid, 'package': package}))


def press_soft_keyboard(plid, package, key_name):
    global xml
    index = util.find_soft_key(key_name, xml, is_samsung)
    if index is None:
        raise Exception('Key ' + key_name + ' does not exist')
    key_x, key_y = index[0], index[1]
    d.click(key_x, key_y)
    log('[press_key]-%s' % json.dumps({'key_name': key_name, 'plid': plid, 'package': package}))


def hide_soft_keyboard(plid, package):
    global xml
    if util.check_soft_keyboard(xml):
        print('Hide soft keyboard')
        d.press('back')
        log('[hide_keyboard]-%s' % json.dumps({'plid': plid, 'package': package}))


def record_popup_window(plid, package):
    global current_popup_window
    current_popup_window = util.get_current_window(d)
    log('[record_popup_window]-%s' % json.dumps({'window': current_popup_window, 'plid': plid, 'package': package}))


def close_popup_window(plid, package):
    global current_popup_window
    if current_popup_window is not None:
        window = util.get_current_window(d)
        if window == current_popup_window:
            d.press('back')
            log('[hide_popup_window]-%s' % json.dumps({'window': current_popup_window, 'plid': plid, 'package': package}))
            current_popup_window = None


def clean_up():
    global sessions
    print('Clean Up....')
    if sessions is not None:
        for session in sessions:
            session.detach()


def detect_webview(session):
    # Get WebView handle
    instrument_script = session.create_script(util.instrument_WebView())
    instrument_script.on('message', get_instrument_WebView_message)
    instrument_script.load()


@error_handler
def get_instrument_WebView_message(message, data):
    global curr_webview_address
    print('[WebView]: ', message)
    curr_webview_address = util.get_view_address(message['payload']['webview'])


def perform_click_event(session, plid, package, tap_type, x, y, duration, view_type):
    global action_count
    global view_hierarchy

    if view_type == 'Activity':
        candidates = util.find_component_candidates(view_hierarchy, x, y)
        # Instrument
        instrument_script = None
        code = util.instrument_view([candidate['classname'] for candidate in candidates] + ['android.view.View'], [candidate['address'] for candidate in candidates], action_count)
        instrument_script = session.create_script(code)
        instrument_script.on('message', get_instrument_view_message)
        instrument_script.load()
        if tap_type == 'LongTap':
            d.long_click(x, y, duration)
        elif tap_type == 'Tap':
            d.long_click(x, y, duration)
        elif tap_type == 'DoubleTap':
            d.double_click(x, y, 0.1)

        # time.sleep(1)
        instrument_script.unload()
        log('[click]-%s' % json.dumps({'tap_type': tap_type, 'x': x, 'y': y, 'duration': duration, 'candidate': candidates, 'view_type': view_type, 'plid': plid, 'package': package}))

    else:
        # Dialog & PopupWindow
        # command `adb shell dumpsys activity top` fails to extract view hierarchy of Dialog & PopupWindow
        if tap_type == 'LongTap':
            d.long_click(x, y, duration)
        elif tap_type == 'Tap':
            d.long_click(x, y, duration)
        elif tap_type == 'DoubleTap':
            d.double_click(x, y, 0.1)
        log('[click]-%s' % json.dumps({'tap_type': tap_type, 'x': x, 'y': y, 'duration': duration, 'view_type': view_type, 'plid': plid, 'package': package}))


@error_handler
def get_instrument_view_message(message, data):
    msg = '[ReplayViewInstrumentation]: %s' % json.dumps(message)
    log(msg, is_action=False)
    # print('[ReplayViewInstrumentation]: %s' % json.dumps(message))


def perform_swipe_event(plid, package, pointers, duration=0.01):
    d.swipe_points(pointers, duration)
    log('[swipe]-%s' % json.dumps({'pointers': pointers, 'duration': duration, 'plid': plid, 'package': package}))


def perform_key_event(plid, package, key_code):
    d.press(key_code)
    log('[press]-%s' % json.dumps({'key_code': key_code, 'plid': plid, 'package': package}))


def webview_set_text(session, input_selector, text, webview_classname, package_name):
    # Set Text
    global curr_webview_address
    code = util.webview_set_text(input_selector, text, webview_classname, curr_webview_address, package_name)
    instrument_script = session.create_script(code)
    instrument_script.on('message', get_webview_set_text_message)
    instrument_script.load()


def webview_set_text_with_u2(plid, package, text):
    d(focused=True).set_text(text)
    log('[webview_set_text]-%s' % json.dumps({'text': text, 'plid': plid, 'package': package}))


@error_handler
def get_webview_set_text_message(message, data):
    msg = '[WebViewSetText]-%s' % json.dumps(message)
    log(msg, is_action=False)


def instrument_chrome_client(session):
    code = util.instrument_chrome_client()
    script = session.create_script(code)
    script.on('message', get_instrument_chrome_client_message)
    script.load()


@error_handler
def get_instrument_chrome_client_message(message, data):
    msg = '[Console]-%s' % json.dumps(message)
    log(msg, is_action=False)


def instrument_low_level_sensor(session, listener_classname_dict):
    code = util.instrument_low_level_sensors(listener_classname_dict)
    script = session.create_script(code)
    script.on('message', get_instrument_low_level_sensor_message)
    script.load()


@error_handler
def get_instrument_low_level_sensor_message(message, data):
    msg = '[onSensorChanged]-%s' % json.dumps(message)
    log(msg, is_action=False)


def instrument_getlastknownlocation(session, get_location_classname_dict):
    code = util.instrument_getlastknownlocation(get_location_classname_dict)
    script = session.create_script(code)
    script.on('message', get_instrument_getlastknownlocation)
    script.load()


@error_handler
def get_instrument_getlastknownlocation(message, data):
    msg = '[getLastKnownLocation]-%s' % json.dumps(message)
    log(msg, is_action=False)


def instrument_onlocationchanged(session, on_location_classname_dict):
    code = util.instrument_onlocationchanged(on_location_classname_dict)
    script = session.create_script(code)
    script.on('message', get_instrument_onlocationchanged)
    script.load()


@error_handler
def get_instrument_onlocationchanged(message, data):
    msg = '[onLocationChanged]-%s' % json.dumps(message)
    log(msg, is_action=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--serial', help='device serial, check by `adb devices`', required=False)
    parser.add_argument('--trace', help='trace log', required=True)
    parser.add_argument('--path', help='save path', required=True)
    parser.add_argument('--pids', nargs='+', help='list of pid', required=True)
    parser.set_defaults(samsung=False)
    parser.add_argument("--samsung", help="Is samsung ?", action="store_true")
    args = parser.parse_args()

    is_samsung = args.samsung
    save_path = args.path
    pids = [int(p) for p in args.pids]

    if not preprocess_path():
        print('Save path not found')
        sys.exit()

    all_devices = frida.enumerate_devices()
    if args.serial:
        print('Serial: ', args.serial)
        device = frida.get_usb_device(args.serial)
    else:
        device = frida.get_usb_device()

    sessions = [device.attach(pid) for pid in pids]
    trace_fd = open(args.trace, 'w')

    try:
        # for session in sessions:
        #     detect_webview(session)
        # instrument_chrome_client()
        post_action(0)
"""
    return [code]


def replace_package_name(rid, package_name):
    if rid is None:
        return ''
    idx = rid.find(':id/')
    if idx == -1:
        return rid
    prefix = rid[:idx]
    if prefix.lower() == 'app':
        return package_name + rid[idx:]
    return rid


def append_script(action, script, time_interval=None):
    script.append('        ' + action)
    if time_interval is None:
        script.append('        post_action(%f)' % 0.0)
    else:
        script.append('        post_action(%f)' % time_interval)


def check_hide_keyboard(events, curr_idx, curr_event):
    target_text_view_id = curr_event.get_text_view_id()
    is_perform = True
    for idx in range(curr_idx + 1, len(events)):
        if events[idx].msg_type == event.Event.TYPE_EVENT:
            curr_text_view_id = events[idx].get_text_view_id()
            if curr_text_view_id is not None and curr_text_view_id == target_text_view_id:
                is_perform = False
            break
    if is_perform:
        for idx in range(curr_idx + 1, len(events)):
            if events[idx].msg_type == event.Event.KEY_EVENT and events[idx].intent == event.KeyEvent.HIDE_KEYBOARD_INTENT:
                return False
        return True
    else:
        return False


def check_duplicate_key_event(events, curr_idx, curr_event):
    """
    Keyevent recorded by TextView.onKeyPreIme may be the same as what activity or dialog records
    Return True if duplicate
    """
    down_time = curr_event.down_time
    key_code = curr_event.key_code
    for idx in range(curr_idx + 1, len(events)):
        if events[idx].msg_type == event.Event.KEY_EVENT:
            if down_time == events[idx].down_time  and events[idx].key_code == key_code:
                if curr_event.intent is not None:
                    events[idx].intent = curr_event.intent
                return True
    return False


def check_webview_key_event(events, curr_idx, curr_event):
    """
    If the target of next webview key event is the same as current event, then we escape current event; otherwise, generate action
    """
    if curr_idx + 1 < len(events) and events[curr_idx + 1].msg_type == event.Event.WEBVIEW_KEY_EVENT:
        curr_input_attrs = curr_event.input_attrs
        next_input_attrs = events[curr_idx+1].input_attrs
        if curr_input_attrs['name'] == next_input_attrs['name'] and curr_input_attrs['id'] == next_input_attrs['id'] and curr_input_attrs['type'] == next_input_attrs['type']:
            return False
    return True


def append_end_snippet(script):
    script.append("""
    except Exception as e:
        print(e)
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        print(traceback_str)
    clean_up()
    if trace_fd is not None:
        trace_fd.close()
    """)


def generate_script(events):
    pid_set = set()
    active_events, low_level_sensor_events, get_location_events, on_location_events = list(), list(), list(), list()
    for ev in events:
        pid_set.add(ev.plid)
        if ev.msg_type == event.Event.LOW_LEVEL_SENSOR_EVENT:
            low_level_sensor_events.append(ev)
        elif ev.msg_type == event.Event.LOCATION_EVENT:
            if ev.location_type == event.LocationEvent.GET_LAST_KNOWN_LOCATRION:
                get_location_events.append(ev)
            else:
                on_location_events.append(ev)
        else:
            active_events.append(ev)

    script = init_script()
    messages = list()
    sensor_events = dict()

    if len(low_level_sensor_events):
        listener_classnames_per_pid = [dict() for i in range(len(pid_set))]
        for se in low_level_sensor_events:
            listener_classname_dict = listener_classnames_per_pid[se.plid]
            if se.listener_classname not in listener_classname_dict:
                listener_classname_dict[se.listener_classname] = dict()
            st = se.sensor_type
            if st not in listener_classname_dict[se.listener_classname]:
                listener_classname_dict[se.listener_classname][st] = {
                    'values': list(),
                    'index': 0,
                }
            listener_classname_dict[se.listener_classname][st]['values'].append(se.values)
        print('Low level sensor: ', len(low_level_sensor_events))
        pprint(listener_classnames_per_pid)
        for idx, listener_classname_dict in enumerate(listener_classnames_per_pid):
            append_script('instrument_low_level_sensor(sessions[%d], %s)' % (idx, json.dumps(listener_classname_dict)), script)
        sensor_events['low_level_sensor'] = listener_classnames_per_pid

    if len(get_location_events) > 0:
        get_location_classname_per_pid = [dict() for i in range(len(pid_set))]
        for le in get_location_events:
            get_location_classname_dict = get_location_classname_per_pid[le.plid]
            if le.classname not in listener_classname_dict:
                get_location_classname_dict[le.classname] = dict()
            provider = le.provider
            if provider not in get_location_classname_dict[le.classname]:
                get_location_classname_dict[le.classname][provider] = {
                    'values': list(),
                    'index': 0
                }
            get_location_classname_dict[le.classname][provider]['values'].append(le.location_info)

        print('GetLastKnownLocation: ', len(get_location_events))
        pprint(get_location_classname_per_pid)
        for idx, get_location_classname_dict in enumerate(get_location_classname_per_pid):
            append_script('instrument_getlastknownlocation(sessions[%d], %s)' % (idx, json.dumps(get_location_classname_dict)), script)
        sensor_events['get_location_events'] = get_location_classname_per_pid

    if len(on_location_events) > 0:
        on_location_classname_per_pid = [dict() for i in range(len(pid_set))]
        for le in on_location_events:
            on_location_classname_dict = on_location_classname_per_pid[le.plid]
            if le.classname not in listener_classname_dict:
                on_location_classname_dict[le.classname] = {
                    'values': list(),
                    'index': 0
                }
            on_location_classname_dict[le.classname]['values'].append(le.location_info)

        print('OnLocationChanged: ', len(on_location_events))
        pprint(on_location_classname_per_pid)
        for idx, on_location_classname_dict in enumerate(on_location_classname_per_pid):
            append_script('instrument_onlocationchanged(sessions[%d], %s)' % (idx, json.dumps(on_location_classname_dict)), script)
        sensor_events['on_location_events'] = on_location_classname_per_pid

    double_tap_flag = False
    last_end_ts = 0
    if len(active_events) > 0:
        last_end_ts = float(active_events[0].end_ts)
    for eidx, ev in enumerate(active_events):
        if eidx < len(active_events) - 1:
            begin_ts = float(active_events[eidx+1].begin_ts)
            time_interval = begin_ts - last_end_ts
            if time_interval < 0:
                time_interval = 0
            last_end_ts = float(active_events[eidx+1].end_ts)
        else:
            time_interval = 0

        if double_tap_flag:
            print('last one is doubleTap.')
            double_tap_flag = False
            continue

        if ev.msg_type == event.Event.TOUCH_EVENT:
            if ev.event_type == 'TouchEvent':
                delta_time = time_interval
                # Identify double tap
                if eidx + 1 < len(active_events) and active_events[eidx+1].msg_type == event.Event.TOUCH_EVENT and active_events[eidx+1].event_type == 'TouchEvent' and delta_time < 0.3 and delta_time > 0.04:
                    double_tap_flag = True
                    append_script('perform_click_event(sessions[%d], %d, "%s", "%s", %f, %f, %f, "%s")' % (ev.plid, ev.plid, ev.package, 'DoubleTap', ev.x, ev.y, ev.duration, ev.view_type), script, time_interval)
                else:
                    append_script('perform_click_event(sessions[%d], %d, "%s", "%s", %f, %f, %f, "%s")' % (ev.plid, ev.plid, ev.package, ev.tap_type, ev.x, ev.y, ev.duration, ev.view_type), script, time_interval)
            elif ev.event_type == 'SwipeEvent':
                append_script('perform_swipe_event(%d, "%s", %s, %f)' % (ev.plid, ev.package, str(ev.pointers), ev.time_interval), script, time_interval)
            messages.append(ev.record_msg())
        elif ev.msg_type == event.Event.KEY_EVENT:
            if not check_duplicate_key_event(active_events, eidx, ev):
                # Not duplicate event
                append_script('perform_key_event(%d, "%s", %s)' % (ev.plid, ev.package, str(ev.key_code)), script, time_interval)
                messages.append(ev.record_msg())
        elif ev.msg_type == event.Event.TYPE_EVENT:
            if ev.action_type == event.InputEvent.TYPE_ACTION:
                # Check if TextView exists
                resource_id = replace_package_name(ev.get_text_view_resource_id(), ev.package)
                bounds = ev.get_text_view_bounds()
                text = ev.text
                append_script('set_text(%d, "%s", "%s", "%s", "%s")' % (ev.plid, ev.package, resource_id, bounds, text), script, time_interval)

                msg = ev.record_msg()
                msg['text_view_rid'] = replace_package_name(msg['text_view_rid'], ev.package)
                messages.append(msg)

                if check_hide_keyboard(active_events, eidx, ev):
                    pass
                    # append_script('hide_soft_keyboard()', script)
                    # messages.append({
                    #     'msg_type': event.Event.TYPE_EVENT,
                    #     'event': 'InputEvent',
                    #     'action_type': event.InputEvent.HIDE_ACTION
                    # })
            else:
                # Action
                key_name = ev.get_editor_action()
                if key_name is None:
                    raise Exception('Parse Fail')
                append_script('press_soft_keyboard(%d, "%s", "%s")' % (ev.plid, ev.package, key_name), script, time_interval)

                msg = ev.record_msg()
                msg['text_view_rid'] = replace_package_name(msg['text_view_rid'], ev.package)
                messages.append(msg)

                if check_hide_keyboard(active_events, eidx, ev):
                    pass
                    # append_script('hide_soft_keyboard()', script)
                    # messages.append({
                    #     'msg_type': event.Event.TYPE_EVENT,
                    #     'event': 'InputEvent',
                    #     'action_type': event.InputEvent.HIDE_ACTION
                    # })
        elif ev.msg_type == event.Event.ACTION_EVENT:
            # Popup window
            messages.append(ev.record_msg())
            if ev.action == event.PopupWindowEvent.SHOW:
                # Show
                append_script('record_popup_window(%d, "%s")' % (ev.plid, ev.package), script, time_interval)
            else:
                # Hide
                append_script('close_popup_window(%d, "%s")' % (ev.plid, ev.package), script, time_interval)
        elif ev.msg_type == event.Event.WEBVIEW_PAGE_LOADED:
            # WebView Page loaded
            messages.append(ev.record_msg())
            # Find webview instance
        elif ev.msg_type == event.Event.WEBVIEW_KEY_EVENT:
            # WebView key event
            if check_webview_key_event(active_events, eidx, ev):
                messages.append(ev.record_msg())
                # Find focused element in webview, and set text
                # append_script("webview_set_text('%s', '%s', '%s', '%s')" % (ev.generate_query_selector(), ev.text, ev.get_webview_class(), ev.package), script, time_interval)
                append_script('webview_set_text_with_u2(%d, "%s", "%s")' % (ev.plid, ev.package, ev.text), script)

    append_end_snippet(script)
    replay_script = '\n'.join(script)
    return replay_script, messages, sensor_events