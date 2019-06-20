# coding=utf8

from __future__ import print_function
import re
import os
import json
import copy
import time
import signal
import platform
import argparse
import frida, sys
from pprint import pprint
from record_inputs import record_inputs_on_dialog as dialog
from record_inputs import record_inputs_on_activity as activity
from record_inputs import record_inputs_on_popupwindow as popupwindow
from record_inputs import record_inputs_on_webview as webview
from record_inputs import instrument_classloader as classloader
from record_inputs import record_low_level_sensor as low_sensor
from record_inputs import record_location as location
from record_inputs import record_soft_keyboard_inputs as soft_keyboard
from record_inputs import record_utils as ru


file_descriptor = None
sessions = None


def load_activity(activities_path):
    all_activities = list()
    with open(activities_path, 'r') as f:
        package_activities = json.load(f)
        for package, activities in package_activities.items():
            all_activities += activities
    return all_activities


def clean_up():
    global sessions
    print('Clean Up....')
    if sessions is not None:
        for session in sessions:
            session.detach()


# Enumerate Loaded classes
def get_loaded_classes(package):
    hook_code = """
        Java.perform(function(){
            var package = '%s';
            Java.enumerateLoadedClasses(
                {
                    onMatch: function(className){
                        var isSensorEventListener = false;
                        var isLocationListener = false;
                        if(className.toLowerCase().startsWith(package)){
                            var classInstance = Java.use(className);
                            var proto = classInstance.__proto__
                            // Inspect SensorEventListener
                            isSensorEventListener = proto.hasOwnProperty('onSensorChanged') && proto.hasOwnProperty('onAccuracyChanged');
                            // Inspect LocationListener
                            isLocationListener = proto.hasOwnProperty('onLocationChanged') && proto.hasOwnProperty('onProviderDisabled') && proto.hasOwnProperty('onProviderEnabled')
                        }
                        send({
                            className: className,
                            isSensorEventListener: isSensorEventListener,
                            isLocationListener: isLocationListener
                        });
                    },
                    onComplete: function(){
                        send('Done');
                    }
                }
            );
        })
    """ % (package)
    return hook_code


def get_loaded_classes_message(p_local_idx, pid, package, session, fd, loaded_activities,
                               declared_activites,
                               exist_activity_dispatchTouchEvent_handle,
                               exist_activity_dispatchKeyEvent_handle,
                               exist_view_onTouchEvent_handle,
                               webclient_classes,
                               chromeclient_classes,
                               exist_sensorListener_handle,
                               exist_locationListener_handle):
    @ru.error_handler
    def wrapper(message, data):

        payload = message['payload']
        if payload == 'Done':

            # Dialog
            dialog_script = session.create_script(dialog.instrument_dialog())
            dialog_script.on('message', dialog.get_instrument_dialog_message(p_local_idx, package, fd))
            dialog_script.load()

            # Activity
            code = activity.instrument_activity(loaded_activities, exist_activity_dispatchTouchEvent_handle, exist_activity_dispatchKeyEvent_handle, True)
            activity_script = session.create_script(code)
            activity_script.on('message', activity.get_instrument_activity_message(p_local_idx, package, fd, exist_activity_dispatchTouchEvent_handle, exist_activity_dispatchKeyEvent_handle))
            activity_script.load()

            # PopupWindow
            popup_window_script = session.create_script(popupwindow.instrument_PopupWindow())
            popup_window_script.on('message', popupwindow.get_instrument_PopupWindow_message(p_local_idx, package, session, fd, exist_view_onTouchEvent_handle))
            popup_window_script.load()

            # WebView
            webview_script = session.create_script(webview.instrument_WebView())
            webview_script.on('message', webview.get_instrument_WebView_message(p_local_idx, package, session, fd, webclient_classes, chromeclient_classes))
            webview_script.load()

            # ClassLoader
            classloader_script = session.create_script(classloader.instrument_ClassLoader())
            classloader_script.on('message', classloader.get_instrument_ClassLoader_message(p_local_idx, package, session,
                                                                                            fd,
                                                                                            declared_activites,
                                                                                            loaded_activities,
                                                                                            exist_activity_dispatchTouchEvent_handle,
                                                                                            exist_activity_dispatchKeyEvent_handle))
            classloader_script.load()

            # SensorManager
            sensor_manager_script = session.create_script(low_sensor.instrument_sensor_manager())
            sensor_manager_script.on('message', low_sensor.get_instrument_sensor_manager_message(p_local_idx, package, session, fd, exist_sensorListener_handle))
            sensor_manager_script.load()

            # Location
            location_manager_script = session.create_script(location.instrument_location_manager())
            location_manager_script.on('message', location.get_instrument_location_manager_message(p_local_idx, package, session, fd, exist_locationListener_handle))
            location_manager_script.load()

            # SpannerStringBuilder
            _spanner_string_script = session.create_script(soft_keyboard.instrument_SpannableStringBuilder())
            _spanner_string_script.on('message', soft_keyboard.get_instrument_SpannableStringBuilder_message(p_local_idx, package, fd))
            _spanner_string_script.load()

            # Keyboard Action
            editable_input_connection = session.create_script(soft_keyboard.instrument_EditableInputConnection())
            editable_input_connection.on('message', soft_keyboard.get_instrument_EditableInputConnection_message(p_local_idx, package, fd))
            editable_input_connection.load()

            # TextView onKeyPreIme
            textview_script = session.create_script(soft_keyboard.instrument_onKeyPreIme())
            textview_script.on('message', soft_keyboard.get_instrument_onKeyPreIme_message(p_local_idx, package, fd))
            textview_script.load()

            print('%d, %s, Instrumentation Finished' % (pid, package))

        else:
            class_name = payload['className']
            class_name = class_name.lower().split('$')[0]
            for act in declared_activites:
                if act.lower() in class_name:
                    loaded_activities.add(act)
                    print('[ClassLoadedFromEnumerate]: %s' % act)
                    break
            if payload['isSensorEventListener']:
                _code = low_sensor.instrument_sensor_listener(None, payload['className'], exist_sensorListener_handle)
                _script = session.create_script(_code)
                _script.on('message', low_sensor.get_instrument_sensor_listener_message(fd, exist_sensorListener_handle))
                _script.load()
            if payload['isLocationListener']:
                _code = location.instrument_location_listener(None, payload['className'], exist_locationListener_handle)
                _script = session.create_script(_code)
                _script.on('message', location.get_instrument_location_listener_message(fd, exist_locationListener_handle))
                _script.load()
    return wrapper

def main(device, packages, pids, trace):
    global sessions
    global file_descriptor
    declared_activites = [set(load_activity('%s_activities.json' % p)) for p in packages]
    sessions = [device.attach(pid) for pid in pids]
    file_descriptor = open(trace, 'w')
    loaded_activities = [set() for i in range(len(pids))]
    exist_activity_dispatchTouchEvent_handle = [set() for i in range(len(pids))]
    exist_activity_dispatchKeyEvent_handle = [set() for i in range(len(pids))]
    exist_view_onTouchEvent_handle = [set() for i in range(len(pids))]
    webclient_classes = [set() for i in range(len(pids))]
    chromeclient_classes = [set() for i in range(len(pids))]
    exist_sensorListener_handle = [set() for i in range(len(pids))]
    exist_locationListener_handle = [set() for i in range(len(pids))]
    for i in range(len(sessions)):
        enumerate_class_script = sessions[i].create_script(get_loaded_classes(packages[i]))
        enumerate_class_script.on('message', get_loaded_classes_message(
            i, pids[i], packages[i], sessions[i], file_descriptor, loaded_activities[i], declared_activites[i],
            exist_activity_dispatchTouchEvent_handle[i], exist_activity_dispatchKeyEvent_handle[i],
            exist_view_onTouchEvent_handle[i], webclient_classes[i],
            chromeclient_classes[i], exist_sensorListener_handle[i],
            exist_locationListener_handle[i]
        ))
        enumerate_class_script.load()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--serial', help='device serial, check by `adb devices`', required=False)
    parser.add_argument('--trace', help='trace log', required=True)
    parser.add_argument('--pids', nargs='+', help='list of pid', required=True)
    parser.add_argument('--packages', nargs='+', help='list of package name', required=True)
    args = parser.parse_args()
    print(args)

    pids = [int(p) for p in args.pids]
    packages = args.packages
    assert len(pids) == len(packages)
    trace = args.trace

    print('Packages: ', packages)
    print('Pids: ', pids)
    print('Device Serial: ', args.serial)

    os_platform = platform.system().lower()

    # Emulator
    all_devices = frida.enumerate_devices()
    if args.serial:
        print('Serial: ', args.serial)
        device = frida.get_usb_device(args.serial)
    else:
        device = frida.get_usb_device()

    main(device, packages, pids, trace)

    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        while True:
            value = input('[Option]: 1) exit 2) clear\n')
            if value.lower() == 'exit':
                raise KeyboardInterrupt()
            elif value.lower() == 'clear':
                # Clear Screen
                if os_platform == 'windows':
                    os.system('cls')
                else:
                    os.system('clear')
    except KeyboardInterrupt:
        if file_descriptor is not None:
            file_descriptor.close()
        clean_up()
        sys.exit()
