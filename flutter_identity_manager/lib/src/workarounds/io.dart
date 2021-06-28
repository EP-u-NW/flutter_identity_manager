import 'dart:io' show Platform;

import 'package:flutter_identity_manager_android/flutter_identity_manager_android.dart';
import 'package:flutter_identity_manager_ios/flutter_identity_manager_ios.dart';
import 'package:flutter_identity_manager_platform_interface/flutter_identity_manager_platform_interface.dart';

// A workaround for flutter/flutter#52267
// TODO: revise once the issue got resolved
void _flutterIssue52267Workaround() {
  if (Platform.isAndroid) {
    FlutterIdentityManagerPlatform.instance =
        new FlutterIdentityManagerAndroid();
  }
  if (Platform.isIOS) {
    FlutterIdentityManagerPlatform.instance = new FlutterIdentityManagerIOS();
  }
}

void apply() {
  _flutterIssue52267Workaround();
}
