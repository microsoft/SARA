## SARA

---

A record-and-replay tool for Android applications.

All the evaluation artifacts (including scenario descriptions, screenshots, view hierarchies, replay scripts, and a demon video) are all available on our project [website](https://sites.google.com/view/sara-record-and-replay).
Such artifacts are valuable for further research, e.g., Android Layout Program Synthesis.

## Requirements
---

* Java 8 (for supporting Apktool)
* Python 3.6.6
* ADB (for connecting Android devices)
* [Apktool](https://ibotpeaches.github.io/Apktool/) (for unpacking an apk)

Run `pip install -r requirements.txt` to install the following Python libraries:
* [bs4](https://pypi.org/project/beautifulsoup4/) (A python library that makes it easy to parse xml)
```pip install bs4```
* [Frida](https://www.frida.re/) (A dynamic instrumentation toolkit) 
```pip install frida-tools```
* [Uiautomator2](https://github.com/openatx/uiautomator2) (Android Uiautomator2 Python Wrapper)

## Setup Android Device
---

In this setup, we aim to run the Frida, a dynamic instrumentation toolkit, in the Android device.
Frida can be runned either with root access or without root access.
In our experiments, we simply run it with root access.
In the followings, we demonstrate how to run frida in both ways.

### Running Frida with root access
####  Physical Device

1. Root the Device.

Unfortunately, there does not exist a gloden script for autoamting the process of rooting deivce, as the ways to root depends on the device manufacturer and the running system.
In practice, we have to do it case by case.

Taking one of our testing devices, Samsung Galaxy A8, as an example, we strictly followed the guidence in https://www.skyneel.com/root-samsung-galaxy-a8-sm-a8000 to root the device.

If no rooted devices or actionable guidences at hand, we recommend testing with Android emulator, and refer to the instructions in Android Emulator.

2. Push the file `tools/frida-server` to `/data/local/tmp/frida-server`

```
adb push ./tools/frida-server /data/local/tmp/frida-server
```

3. Run the frida-server
```
adb root
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

#### Android Emulator

1. Setup an Android Emulator

    * In Android Studio, go to Tools -> Android -> AVD Manager.
    * Press the "+ Create Virtual Device" button.
    * Choose the type of hardware you'd like to emulate. 
    * Select an OS version to load on the emulator. We recommend selecting those images labeled with "Google API", because we can get the root access directly.
    * press "Finish" to create the virtual device.

2. Run the emualtor.
3. Push the corresponding file to the device depending on the CPU/ABI of the emulator's image.

If it is `arm`, then 
```
adb push ./tools/frida-server /data/local/tmp/frida-server
```
It it is `x86`, then
```
adb push ./tools/frida-server-12.0.7-android-x86 /data/local/tmp/frida-server
```
It it is `x86_64`, then
```
adb push ./tools/frida-server-12.0.7-android-x86_64 /data/local/tmp/frida-server
```

4. Run the frida-server
```
adb root
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### Running Firda  without root access
Note that we can also use Frida to instrument the app under record without rooting the device by repackaging the app to include a firda library: 

1. Use the `apktool` to decode the APK
```
apktool d myapp.apk -o unpacked_apk
```

2. Copy the frida library `./tools/libfrida-gadget.so` to the directory `./unpacked_apk/lib` of the unpacked apk.

3. Inject a `System.loadLibrary("frida-gadget")` call into the bytecode of the app, ideally before any other bytecode executes or any native code is loaded. 
In practice, we can inject it in the Application class or the Main Activity.
We have to take this step manually by finding the entry point of the app in the AndroidManifest.xml.

4. Add the Internet permission to the AndroidManifest.xml
```
<uses-permission android:name="android.permission.INTERNET" />
```

5. Repackage the application with `apktool`.
```
apktool b -f -d unpacked_apk
```

6. Sign the repackaged APK.
The apk must be signed before it is run on a device. 
Create a key if you don't have an existing one. 
```
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name \
                   -keyalg RSA -keysize 2048 -validity 10000

jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my_application.apk alias_name

# Verify apk
jarsigner -verify -verbose -certs my_application.apk

zipalign -v 4 my_application.apk my_application-aligned.ap
```

Once the repackaged app runs on the Android device, it will start the Frida server.

## Running in Virtual Machine
---

If you failed to setup the environments or the Android device, we prepare a virtual machine for evaluation where all the required environments and an Android emulator have been setup.
Download the virtual machine [here](https://1drv.ms/u/s!AtmIX3lODv4sgoZzOUzbUzEJGskLbw?e=VfkMfL), and load the virtual machine with VMWare workstation 14.1.1.

The project is located in `/home/sara/SARA`. 
```
cd /home/sara/SARA
./start_emulator.sh # Start the Android emulator
./setup_device.sh   # Run the frida-server
```

## Setup App
---

To record motion inputs and key inputs, SARA needs to instrument all the activities declared in the app.
We can easily obtain all the activities by reading the AndroidManifest.xml.

1. Install the app on the device
```
adb install amaze_filemanager.apk
```
2. Parse the AndroidManifest.xml
```
./parse_apk.sh amaze_filemanager.apk com.amaze.filemanager
```
where "com.amaze.filemanager" is the package name of the app.

3. Run the app on device.

## Record
---

1. Check the process id of the app
```
adb shell "ps | grep com.amaze.filemanager"
```
2. Start the record process, which will log all the inputs in the trace file.
```
python ./record.py --trace ./trace.log --packages com.amaze.filemanager --pids 1277
```
If the app under record interacts with other apps or other processes (an app can start multiple processes), it is necessary to include the package names and the process ids of the other apps.

For example, the app `com.amaze.filemanager` interacts with the system file manager, we can record the inputs with the following commands,
```
python ./record.py --trace ./trace.log --packages com.amaze.filemanager com.android.documentsui --pids 1277 4288
```
where `com.android.documentui` and 4288 are the package name and the process id of the system file manager, respectively.

3. When the messages `pid, package name, Instrumentation Finished` show on the console, we can play with the app to record scenarios. We have supported motion inputs, key inputs, low level sensor inputs (e.g., ACCELEROMETER, GRAVITY, LIGHT, etc.) and location sensor inputs.

4. To terminate the record, input `exit` on the console. Then, all the recorded inputs will be written to the trace file.

## Self-Replay
---

1. Parse the trace file, which will outputs a self-replay script `trace_replay.py` and all the sensor events `trace_replay_sensor_events.log`.

```
python ./parse_events.py --trace ./trace.log
```

2. Run the self-reply script, whill will capture widgets information.
The screenshot and view hierarchy will be saved in the directory `./self_replay` when each action is performed.
```
python ./trace_replay.py --path ./self_replay --trace ./self_replay_trace.log --pids 1277 4288
```
**It is important to note the order of pids should be the same as the one specified in record.**

## Replay
---
1. Generate the replay script based on the screen configurations of the recording device and replaying device.
In the following example, `1080,1920,480` is the screen configurations of the recording device; `1080,2220,420` is the screen configurations of the replaying device.
An replay script `self_replay_trace_widget_replay_1080_2220_420.py` for the replaying device will be generated.
```
python ./transform.py --logdir ./self_replay --trace ./self_replay_trace.log --sensor ./trace_replay_sensor_events.log --sdevice 1080,1920,480 --tdevice 1080,2220,420
```
To retrieve the screen configuration of the Android device, run the commands:
```
size: adb shell wm size
dpi: adb shell wm density
```

2. Run the replay script.
```
python ./self_replay_trace_widget_replay_1080_2220_420.py --path ./widget_replay --pids 1277 4288
```
**It is important to note the order of pids should be the same as the one specified in record.**

## Plan for Improvement
---

1. Provide a graphical user interface for SARA or provide a plugin for [Smartphone Test Farm](https://github.com/openstf/stf) (STF), which is widely used android devices management platform. We are investingating which option will benefit the industry most.

2. During evaluations, we find that in 7 cases SARA fails to capture the precise timing to replay a motion event during self-replay because in self-replaying phase SARA instruments candidate widgets before performing a motion event.
To solve this problem, we plan to study the average time overhead introduced by instrumentations, and re-calculate the time waiting for a motion event.

3. Frida fails to process classes that implement the Interface `android.text.Editable` which provides rich methods to process input string. We have opened an [issue](https://github.com/frida/frida/issues/588)  for this problem in the issue tracker of Frida but have not yet received a reply. We try to infer input with several heuristic strategies to bypass
the problem in current version, but in some cases we still miss inputs from soft keyboard. We are seeking for a systematic solution for this problem. One possible solution can be recording both the soft keyboard inputs and physical key inputs with ADB command `getevent` like [RERAN](http://www.androidreran.com/) and [appetizer](https://github.com/appetizerio/replaykit).

## Instrumented Android APIs
---

#### Motion Inputs

* `android.app.Activity.dispatchTouchEvents`
* `android.app.Dialog.dispatchTouchEvents`
* `android.widget.PopupWindow.showAsDropDown`
* `android.widget.PopupWindow.showAtLocation`
* `android.widget.PopupWindow.dismiss`
* `android.view.View.onTouchEvent`

#### Physical Key Inputs

* `android.app.Dialog.dispatchKeyEvents`
* `android.app.Activity.dispatchKeyEvents`

#### Soft Keyboard Inputs

* `android.view.inputmethod.BaseInputConnection.beginBatchEdit`
* `android.view.inputmethod.BaseInputConnection.performEditorAction`
* `android.widget.TextView.onKeyPreIme`
* `android.widget.AutoCompleteTextView.onKeyPreIme`
* `android.text.SpannableStringBuilder.toString`


#### Motion and Key Inputs on WebView

* `android.webkit.WebView.setWebViewClient`
* `android.webkit.WebView.setWebChromeClient`
* `android.webkit.WebChromeClient.onConsoleMessage`
* `android.webkit.WebViewClient.onPageFinished`

#### Location Sensor Inputs
* `android.location.LocationManager.getLastKnownLocation`
* `android.location.LocationManager.requestLocationUpdates`
* `android.location.LocationListener.onLocationChanged`

#### Low Level Sensor Inputs

* `android.sensor.SensorManager.registerListener`
* `android.sensor.SensorListener.onSensorChanged`

In SARA, we try to keep it as general as possible.
It is fairly easy to customize the APIs to be instrumented.
