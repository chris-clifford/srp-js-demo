/* global $, jsrp */

function resetUI () {
  $('#statusP0').html('')
  $('#statusP1').html('')
  $('#statusP2').html('')
  $('#statusP3').html('')
  $('#loginMessage').html('')
  $('#regMessage').html('')
}

function registerUser (username, password) {
  var client = new jsrp.client()

  resetUI()

  // debug
  // var a = new Uint8Array('60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393', 'hex')
  // client.debugInit({ username: username, password: password, length: 4096, a: a }, function () {
  client.init({ username: username, password: password, length: 2048 }, function () {
    client.createVerifier(function (err, result) {
      if (err) {
        console.error(err.stack)
      }

      $('#statusP0').append('P0 : START\n')
      $('#statusP0').append('P0 : username : ' + username + '\n')
      $('#statusP0').append('P0 : password : ******\n')
      $('#statusP0').append('P0 : salt : ' + result.salt + '\n')
      $('#statusP0').append('P0 : verifier : ' + result.verifier + '\n')

      $('#statusP0').append('P0 : POST username, salt, and verifier registration data to server\n')
      $.post('http://localhost:3002/api/v8/signup', { email: username, salt: result.salt, verifier: result.verifier, password: password }, function (data) {
        $('#regMessage').html('REGISTERED')

        $('#statusP0').append('P0 : Server returned user.username: ' + data.success + '\n')
        $('#statusP0').append('P0 : Server returned user.salt: ' + data.message + '\n')
      }, 'json')
      .fail(function () {
        $('#statusP0').append('P0 : ERROR : User registration failed! Duplicate user?\n')
      })
    })
  })
}

function confirmPin (username, pin) {

  resetUI()

  $('#statusP1').append('P1 : START\n')
  $('#statusP1').append('P1 : username : ' + username + '\n')
  $('#statusP1').append('P1 : pin : ' + pin + '\n')

  $('#statusP1').append('P1 : POST username and pin to server\n')
  $.post('http://localhost:3002/api/v8/confirm', { email: username, pin: pin }, function (data) {
    $('#regMessage').html('CONFIRMED')

    $('#statusP1').append('P1 : Server returned successfully?: ' + data.success + '\n')
    $('#statusP1').append('P1 : Server returned message: ' + data.message + '\n')
  }, 'json')
  .fail(function () {
    $('#statusP1').append('P1 : ERROR : User confirmation failed! Invalid pin?\n')
  })
}

function loginUser (username, password) {
  var client = new jsrp.client()

  resetUI()

  // debug
  // var a = new Uint8Array('60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393', 'hex')
  // client.debugInit({ username: username, password: password, length: 4096, a: a }, function () {
  client.init({ username: username, password: password, length: 2048 }, function () {
    // Phase 1
    // Send : username and A
    // Receive : salt and B
    // Calculate : M
    //
    var A = client.getPublicKey()
    $('#statusP2').append('P2 : client A : ' + A + '\n')

    $('#statusP2').append('P2 : Sending username and A to server\n')

    $.post('http://localhost:3002/api/v8/login', { username: username, A: A }, function (data) {
      $('#statusP2').append('P2 : Received challenge : ' + data.challenge.salt + '\n')
      client.setSalt(data.challenge.salt)
      $('#statusP2').append('P2 : Received B : ' + data.challenge.B + '\n')
      client.setServerPublicKey(data.challenge.B)

      $('#statusP2').append('P2 : calc M : A : ' + client.ABuf.toString('hex') + '\n')
      $('#statusP2').append('P2 : calc M : B : ' + client.BBuf.toString('hex') + '\n')
      $('#statusP2').append('P2 : calc M : S : ' + client.SBuf.toString('hex') + '\n')
      $('#statusP2').append('P2 : calc M : K : ' + client.KBuf.toString('hex') + '\n')

      var clientM = client.getProof()
      $('#statusP2').append('P2 : calculated client M : ' + clientM + '\n')

      var device_id = '9E069A40-756F-4E43-A71A-160E2B454D5E'
      var device_token = '4396d95d024c5b30db02df5f945066defde127c48d12282bd73f80527c940fb7'
      var today = new Date()
      var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
      var time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
      var device_json = {device_id: device_id, imei: device_id, device_token: device_token, timestamp: date + " " + time + " " + "-0700" }
      // var textBytes = aesjs.utils.utf8.toBytes(device_json)
      // var aesCbc = new aesjs.ModeOfOperation.cbc(key);
      // var encryptedBytes = aesCbc.encrypt(textBytes);

      // Phase 2
      // Send : username and M
      // Receive : H_AMK
      // Confirm client and server H_AMK values match, use shared key K
      //
      $('#statusP3').append('P3 : Sending username and client M to server\n')

      $.post('http://localhost:3002/api/v8/validate_s', { username: username, s_hash: clientM, token: device_json }, function (data) {
        $('#statusP3').append('P3 : Received server H_AMK : ' + data.H_AMK + '\n')

        if (client.checkServerProof(data.H_AMK)) {
          $('#statusP3').append('P3 : H_AMK values match!\n')
          $('#statusP3').append('P3 : Shared Secret K : ' + client.getSharedKey() + '\n')
          $('#loginMessage').html('AUTHENTICATED')
        } else {
          $('#statusP3').append('P3 : ERROR : Auth Failed : Client and server H_AMK did not match.')
        }
      }, 'json')
      .fail(function () {
        $('#statusP1').append('P3 : ERROR : Attempt to authenticate failed. Unknown user?\n')
      })
    }, 'json')
    .fail(function () {
      $('#statusP1').append('P1 : ERROR : Attempt to authenticate failed. Unknown user?\n')
    })
  })
}



$(document).ready(function () {
  'use strict'

  $('#regButton').click(function () {
    registerUser($('#regUsername').val(), $('#regPassword').val())
  })

  $('#confirmButton').click(function () {
    confirmPin($('#confirmUsername').val(), $('#confirmPin').val())
  })

  $('#loginButton').click(function () {
    loginUser($('#loginUsername').val(), $('#loginPassword').val())
    // loginUser('leonardo', 'icnivad')
  })
})
