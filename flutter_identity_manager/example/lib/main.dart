import 'dart:io';
import 'dart:math';
import 'package:flutter/material.dart';
import 'dart:async';
import 'package:flutter_identity_manager/flutter_identity_manager.dart';
import 'package:share/share.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(new MyApp(new Random().nextInt(130131231).toString()));
}

class MyApp extends StatefulWidget {
  final String name;
  MyApp(this.name);
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String get name => widget.name;
  IdentityRequest? request;
  Identity? identity;
  final TextEditingController certInputController = new TextEditingController();

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: new Text('Identity Manager: $name'),
        ),
        body: new Column(
          children: [
            new TextButton(
                onPressed: request != null
                    ? null
                    : () async {
                        request = await IdentityRequest.create(name);
                        await Share.share(request!.publicKey);
                        setState(() {
                          identity = null;
                        });
                      },
                child: new Text('Create Key')),
            new Container(
                child: new Row(
              children: [
                new Container(
                    width: 200,
                    child: TextField(
                      controller: certInputController,
                    )),
                new TextButton(
                    onPressed: request == null
                        ? null
                        : () async {
                            String text = certInputController.text;
                            if (text == '') {
                              print('No input');
                              return;
                            }
                            identity = await request!.complete(text);
                            setState(() {
                              request = null;
                            });
                          },
                    child: new Text('Create Identity'))
              ],
            )),
            new TextButton(
                onPressed: identity != null
                    ? null
                    : () async {
                        identity = await Identity.load(name);
                        setState(() {
                          request = null;
                        });
                      },
                child: new Text('Load Identity')),
            new TextButton(
                onPressed: identity == null
                    ? null
                    : () async {
                        SecurityContext context = new SecurityContext();
                        context.useCertificateChainBytes(identity!.certificate,
                            password: identity!.privateKeyPassword);
                        context.usePrivateKeyBytes(identity!.privateKey,
                            password: identity!.privateKeyPassword);

                        SecureSocket socket = await SecureSocket.connect(
                          'epnw.eu',
                          4453,
                          context: context,
                          onBadCertificate: (certificate) {
                            print('Bad Certificate');
                            return true;
                          },
                        );
                        await Future.delayed(Duration(seconds: 2));
                        await socket.close();
                      },
                child: new Text('Connect')),
            new TextButton(
                onPressed: request != null
                    ? null
                    : () async {
                        IdentityRequest? r = await IdentityRequest.load(name);
                        if (r == null) {
                          print('Could not load public key');
                          return;
                        }
                        request = r;
                        await Share.share(request!.publicKey);
                        setState(() {
                          identity = null;
                        });
                      },
                child: new Text('Load Key')),
            new TextButton(
                onPressed: identity == null
                    ? null
                    : () async {
                        bool success = await identity!.delete();
                        print('Delete identity success: $success');
                        setState(() {
                          identity = null;
                        });
                      },
                child: new Text('Delete Identity')),
            new TextButton(
                onPressed: request == null
                    ? null
                    : () async {
                        bool success = await request!.delete();
                        print('Delete key success: $success');
                        setState(() {
                          request = null;
                        });
                      },
                child: new Text('Delete Key'))
          ],
        ),
      ),
    );
  }
}
