// import ReactNative, { NativeModules } from 'react-native';
//
// export default class DesCrypto {
//     encrypt(text, key, callback) {
//         NativeModules.DesCrypto.encrypt();
//     }
//
//     decrypt(text, key, callback) {
//         NativeModules.DesCrypto.decrypt();
//     }
// }

'use strict';

var ReactNative = require('react-native');
var {
    NativeModules
} = ReactNative;

module.exports = NativeModules.DesCrypto;
