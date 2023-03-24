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

import 'package:convert/convert.dart' show hex;
import 'package:crypto/crypto.dart' show sha256, Hmac;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:http/http.dart' as http;
import 'dart:convert' show json, utf8;

//AWS SSM Version 4
// https://docs.amazonaws.cn/en_us/general/latest/gr/sigv4-signed-request-examples.html
class ResponseException {
  final String message;
  final dynamic data;
  final String errorType;
  final int statusCode;
  ResponseException(this.message, this.data, this.errorType, this.statusCode);
}

class AwsSSM {
  final String region;
  final String userPoolId;
  final String identityPoolId;

  AwsSSM(this.region, this.userPoolId, this.identityPoolId);

  Future<dynamic> getParams(String? idToken, List<String> names) async {
    final credentials = await getCognitoCredentialsForIdentity(idToken);
    final payload = createPayload(names);
    final datetime = await getServerDateTime();
    final headers = createAWS4Header(credentials, payload, datetime);
    return getParameters(headers, payload);
  }

  Future<List<T?>> getListParams<T>(String? idToken, List<String> names) async {
    final params = await getParams(idToken, names);
    return toList<T>(names, params);
  }

  Future<Map<String, T?>> getMapParams<T>(String? idToken, List<String> names) async {
    final params = await getParams(idToken, names);
    return toMap<T>(names, params);
  }

  //_cognitoUserSession!.getIdToken().getJwtToken()
  Future<Map<String, dynamic>> getCognitoCredentialsForIdentity(String? idToken) async {
    final uri = 'https://cognito-identity.$region.amazonaws.com/';
    final headers = {'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': 'AWSCognitoIdentityService.GetId'};
    final body = {
      'IdentityPoolId': identityPoolId,
      'Logins': {'cognito-idp.$region.amazonaws.com/$userPoolId': idToken}
    };
    dynamic data = await _request(uri, headers, body);
    body['IdentityId'] = data?['IdentityId'];
    headers['X-Amz-Target'] = 'AWSCognitoIdentityService.GetCredentialsForIdentity';
    return await _request(uri, headers, body);
  }

  Map<String, dynamic> createPayload(dynamic names, [bool withDecryption = true]) {
    return {'Names': names, 'WithDecryption': withDecryption};
  }

  Map<String, String> createAWS4Header(dynamic credentials, Map<String, dynamic> payload, [String? datetime]) {
    final accessKeyId = credentials['Credentials']['AccessKeyId'];
    final secretKey = credentials['Credentials']['SecretKey'];
    final sessionToken = credentials['Credentials']['SessionToken'];

    datetime ??= getDateTime();

    Map<String, String> headers = {
      'accept': 'application/json',
      'content-type': 'application/x-amz-json-1.1; charset=utf-8',
      'host': 'ssm.$region.amazonaws.com',
      'x-amz-date': datetime,
      'x-amz-target': 'AmazonSSM.GetParameters'
    };

    final canonicalRequest = [
      'POST',
      '/',
      '',
      headers.map((key, value) => MapEntry(key, '$key:$value')).values.join('\n') + '\n',
      headers.keys.join(';'),
      hex.encode(sha256.convert(utf8.encode(json.encode(payload))).bytes)
    ].join('\n');

    final hashedCanonicalRequest = hex.encode(sha256.convert(utf8.encode(canonicalRequest)).bytes);
    final credentialScope = '${datetime.substring(0, 8)}/$region/ssm/aws4_request';
    final stringToSign = ['AWS4-HMAC-SHA256', datetime, credentialScope, hashedCanonicalRequest].join('\n');

    final signingKey = _sign(
        _sign(_sign(_sign(utf8.encode('AWS4$secretKey'), datetime.substring(0, 8)), region), 'ssm'), 'aws4_request');
    final signature = hex.encode(_sign(signingKey, stringToSign));

    headers['Authorization'] = [
      'AWS4-HMAC-SHA256',
      ' Credential=',
      accessKeyId,
      '/',
      credentialScope,
      ', SignedHeaders=',
      headers.keys.join(';'),
      ', Signature=',
      signature
    ].join();
    headers['x-amz-security-token'] = sessionToken;

    return headers;
  }

  Future<dynamic> getParameters(Map<String, String> headers, Map<String, dynamic> payload) async {
    return _request('https://ssm.$region.amazonaws.com/', headers, payload);
  }

  List<T?> toList<T>(List<String> names, dynamic data) {
    ValueSSM parameters = ValueSSM(data).parameters;
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

  Map<String, T?> toMap<T>(List<String> names, dynamic data) {
    ValueSSM parameters = ValueSSM(data).parameters;
    Map<String, T?> values = {};
    for (int i = 0; i < parameters.length; i++) {
      ValueSSM value = parameters.get(i);
      final index = names.indexOf(value.name);
      if (index != -1) {
        values[value.name] = value.value;
      }
    }
    return values;
  }

  List<int> _sign(List<int> key, String message) {
    final hmac = Hmac(sha256, key);
    final dig = hmac.convert(utf8.encode(message));
    return dig.bytes;
  }

  Future<dynamic> _request(String uri, Map<String, String>? headers, Object? body) async {
    dynamic data;
    try {
      final response = await http.post(Uri.parse(uri), headers: headers, body: json.encode(body));
      try {
        data = json.decode(utf8.decode(response.bodyBytes));
      } catch (_) {
        // expect json
      }
      if (response.statusCode < 200 || response.statusCode > 299) {
        String errorType = 'UnknownError';
        for (final header in response.headers.keys) {
          if (header.toLowerCase() == 'x-amzn-errortype') {
            errorType = response.headers[header]!.split(':')[0];
            break;
          }
        }
        throw ResponseException('ResponseException', data, errorType, response.statusCode);
      }
    } catch (ex) {
      rethrow;
    }
    return data;
  }

  String getDateTime() {
    return DateTime.now()
        .toUtc()
        .toString()
        .replaceAll(RegExp(r'\.\d*Z$'), 'Z')
        .replaceAll(RegExp(r'[:-]|\.\d{3}'), '')
        .split(' ')
        .join('T');
  }

  Future<String> getServerDateTime() async {
    if (!kIsWeb) {
      try {
        http.Response res = await http.get(Uri.parse('https://mws.amazonservices.com/'));
        RegExp exp = RegExp(r"timestamp='(.*)'", multiLine: true);
        final match = exp.firstMatch(res.body);
        if (match != null) {
          return match.group(1).toString().replaceAll(RegExp(r'\.\d*Z$'), 'Z').replaceAll(RegExp(r'[:-]|\.\d{3}'), '');
        }
        // ignore: empty_catches
      } catch (e) {}
    }
    return getDateTime();
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