# coding=utf8

import os
import json
import codecs
import argparse
from pathlib import Path
from pprint import pprint
from bs4 import BeautifulSoup


def get_manifest(project_path):
    pathlist = Path(project_path).glob('**/AndroidManifest.xml')
    xmls = list()
    for manifest_path in pathlist:
        xmls.append(str(manifest_path))
    return xmls


def parse_manifest(xml_path):
    activities = list()
    permissions = list()
    features = list()
    package_name = ''
    with codecs.open(xml_path, 'r', encoding='utf8') as f:
        content = f.read()
        _xml = BeautifulSoup(content, 'lxml')
        package_name = _xml.manifest['package']
        # Activities
        for activity in _xml.manifest.application.findAll('activity'):
            name = activity['android:name']
            if name.startswith('.'):
                name = package_name + name
            activities.append(name)
        # Permissions
        for permission in _xml.manifest.findAll('uses-permission'):
            name = permission['android:name']
            permissions.append(name)
        # Features
        for feature in _xml.manifest.findAll('uses-feature'):
            name = feature['android:name']
            features.append(name)
    print("Extract %s == End" % xml_path)
    return activities, permissions, features, package_name


def save_activities(activities, targetpath):
    with open(targetpath, 'w') as f:
        f.write(json.dumps(activities, indent=4))


def save_permissions(permissions, targetpath):
    with open(targetpath, 'w') as f:
        f.write(json.dumps(permissions, indent=4))


def save_features(features, targetpath):
    with open(targetpath, 'w') as f:
        f.write(json.dumps(features, indent=4))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--path', help='Project directory', required=True)
    parser.add_argument('--package', help='package name', required=True)
    args = parser.parse_args()

    package = args.package

    xmls = get_manifest(args.path)
    pprint(xmls)
    all_activities = dict()
    all_permissions = dict()
    all_features = dict()
    for _xml in xmls:
        _activities, _permissions, _features, _package_name = parse_manifest(_xml)
        if _package_name in all_activities:
            all_activities[_package_name] += _activities
            all_permissions[_package_name] += _permissions
            all_features[_package_name] += _features
        else:
            all_permissions[_package_name] = _permissions
            all_activities[_package_name] = _activities
            all_features[_package_name] = _features
    pprint(all_activities)
    pprint(all_permissions)
    pprint(all_features)
    prefix = package + "_"
    save_activities(all_activities, prefix + 'activities.json')
    save_permissions(all_permissions, prefix + 'permissions.json')
    save_features(all_features, prefix + 'features.json')
    