/*
 * Copyright 2021 Developed by David Gofman
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'package:amazon_cognito_identity_dart_2/cognito.dart';
import 'package:amazon_cognito_identity_dart_2/sig_v4.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'dart:convert' show json;

//AWS SSM Version 4
// https://docs.amazonaws.cn/en_us/general/latest/gr/sigv4-signed-request-examples.html
// Error: pub get failed (1; So, because nats_client depends on both flutter_localizations any from sdk and aws_ssm_api any, version solving failed.)

class AwsSSM {

  final String region;
  final CognitoCredentials credentials;
  final AwsSigV4Client awsSigV4Client;

  AwsSSM(this.region, this.credentials) :
        awsSigV4Client = AwsSigV4Client(
            credentials.accessKeyId!, credentials.secretAccessKey!,
            'https://ssm.$region.amazonaws.com',
            sessionToken: credentials.sessionToken,
            serviceName: 'ssm',
            region: region);

  SigV4Request _createRequest(String target, String? datetime, dynamic body) {
    return SigV4Request(awsSigV4Client,
        datetime: datetime,
        method: 'POST', path: '/',
        headers: Map<String, String>.from(
            {'Content-Type': 'application/x-amz-json-1.1; charset=utf-8',
              'X-Amz-Target': target}),
        body: body);
  }

  Future<ValueSSM> _send(SigV4Request request) async {
    http.Response? res;
    Map<String, String> headers = {};
    request.headers!.forEach((key, value) {
      if (value != null) {
        headers[key] = value;
      }
    });
    try {
      res = await http.post(Uri.parse(request.url!), headers: headers, body: request.body);
    } catch (e) {
      throw Exception('SSMError[$res.statusCode] $res');
    }
    if (res.statusCode < 200 || res.statusCode >= 300 || res.body.isEmpty) {
      throw Exception('SSMError[$res.statusCode] ${res.body}');
    }
    return ValueSSM(json.decode(res.body));
  }

  Future<String?> getDateTime() async {
    if (!kIsWeb) {
      try {
        http.Response res = await http.get(Uri.parse('https://mws.amazonservices.com/'));
        RegExp exp = RegExp(r'timestamp="(.*)"', multiLine: true);
        final match = exp.firstMatch(res.body);
        if (match != null) {
          return match.group(1).toString()
              .replaceAll(RegExp(r'\.\d*Z$'), 'Z')
              .replaceAll(RegExp(r'[:-]|\.\d{3}'), '');
        }
        // ignore: empty_catches
      } catch (e) {}
    }
    return Future.value(null);
  }

  Future<ValueSSM> getParameters(List<String> names, {
    bool withDecryption = false,
    String? datetime}) {
    final req = _createRequest('AmazonSSM.GetParameters', datetime, {
      'Names': names, 'WithDecryption': withDecryption
    });
    return _send(req);
  }

  List<T?> getValues<T>(List<String> names, ValueSSM value) {
    ValueSSM parameters = value.parameters;
    List<T?> values = List.filled(parameters.length, null);
    for (int i = 0; i < parameters.length; i++) {
      ValueSSM value = parameters.get(i);
      final index = names.indexOf(value.name);
      if (index != -1) {
        values[index] = value.value;
      }
    }
    return values;
  }
}

class ValueSSM {
  final dynamic _value;
  ValueSSM(this._value);
  ValueSSM get invalidParameters {
    return ValueSSM(_value['InvalidParameters']);
  }
  ValueSSM get parameters {
    return ValueSSM(_value['Parameters']);
  }
  ValueSSM get(int index) {
    return ValueSSM(_value.length > index ? _value[index] : null);
  }
  dynamic prop(String key) {
    return _value[key];
  }
  dynamic get value {
    return prop('Value');
  }
  dynamic get name {
    return prop('Name');
  }
  get length {
    return _value.length;
  }
}