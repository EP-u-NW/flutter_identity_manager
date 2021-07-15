import Flutter
import UIKit

@available(iOS 10.0, *)
public class SwiftFlutterIdentityManagerIosPlugin: NSObject, FlutterPlugin {
    
  public static func register(with registrar: FlutterPluginRegistrar) {
    let instance = SwiftFlutterIdentityManagerIosPlugin()
    
    let channel = FlutterMethodChannel(name: "eu.epnw.flutter_identity_manager", binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    var args : Dictionary<String,Any> = [:];
    if call.arguments != nil{
        args = call.arguments as! Dictionary<String,Any>;
    }
    if(call.method == "generateKey"){
        guard let tag = args["tag"] as? String else {
            result(nil);
            return;
        }
        var attributes = KeyAttributes(tag: tag);
        if let size = args["size"] as? Int  {
            attributes.size = size;
        }
        if let permanent = args["permanent"] as? Bool {
            attributes.permanent = permanent;
        }
        guard let data = CertManager.generateKey(keyAttributes: attributes) else {
            result(nil);
            return;
        }
        result(FlutterStandardTypedData(bytes: data));
        return;
    } else if (call.method == "deleteKey"){
        guard let tag = args["tag"] as? String else {
            result(false);
            return;
        }
        result(CertManager.deleteKey(tag:tag));
        return;
    } else if (call.method == "deleteCert") {
        guard let label = args["label"] as? String else {
            result(false);
            return;
        }
        result(CertManager.deleteCert(label:label));
        return;
    } else if (call.method == "loadPublicKey"){
        guard let tag = args["tag"] as? String else {
            result(nil);
            return;
        }
        guard let data = CertManager.loadPublicKey(tag: tag) else {
            result(nil);
            return;
        }
        result(FlutterStandardTypedData(bytes: data));
        return;
    } else if (call.method == "createIdentity"){
        guard let data = args["data"] as? FlutterStandardTypedData else {
            result(false);
            return;
        }
        guard let label = args["label"] as? String else {
            result(false);
            return;
        }
        result(CertManager.createIdentity(certData: data.data, label: label));
        return;
    } else if (call.method == "loadIdentity"){
        guard let tag = args["tag"] as? String else {
            result(nil);
            return;
        }
        guard let name = args["name"] as? String else {
            result(nil);
            return;
        }
        guard let password = args["password"] as? String else {
            result(nil);
            return;
        }
        guard let data = CertManager.loadIdentity(tag: tag, p12Name: name, p12Password: password) else {
            result(nil);
            return;
        }
        result(FlutterStandardTypedData(bytes: data));
        return;
    } else {
        result(nil);
        return;
    }
    
  }
}
