/*
 * Copyright (C) 2018 Piotr Wittchen
 *
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
package pwittchen.github.com.rxbiometric

import android.content.DialogInterface
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import android.widget.Toast
import androidx.core.app.ActivityCompat
import com.github.pwittchen.rxbiometric.library.RxBiometric
import com.github.pwittchen.rxbiometric.library.throwable.AuthenticationError
import com.github.pwittchen.rxbiometric.library.throwable.AuthenticationFail
import com.github.pwittchen.rxbiometric.library.throwable.BiometricNotSupported
import com.github.pwittchen.rxbiometric.library.validation.RxPreconditions
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.Disposable
import io.reactivex.rxkotlin.subscribeBy
import kotlinx.android.synthetic.main.activity_main.toolbar
import kotlinx.android.synthetic.main.content_main.*
import java.security.*
import javax.crypto.KeyGenerator
import android.security.keystore.KeyGenParameterSpec
import android.util.Base64
import androidx.biometric.BiometricPrompt
import io.reactivex.Observable
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec


class MainActivity : AppCompatActivity() {

  private var disposable: Disposable? = null

  private var encoded : String = ""

  private var lastIv: String = ""

  @RequiresApi(Build.VERSION_CODES.P)
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    setSupportActionBar(toolbar)


    button.setOnClickListener { _ ->
        RxPreconditions
          .canHandleBiometric(this)
          .flatMapObservable {
            if (!it) Observable.error(BiometricNotSupported())
            else {
              val keypair = getAESKey("KUNG KEY")
              val cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                  + KeyProperties.BLOCK_MODE_CBC + "/"
                  + KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .apply {
                  if(encoded.isEmpty()) {
                    init(Cipher.ENCRYPT_MODE, keypair)
                  }else{
                    init(Cipher.DECRYPT_MODE, keypair, IvParameterSpec(Base64.decode(lastIv, Base64.URL_SAFE)))
                  }
                }
              var cryptoObject = BiometricPrompt.CryptoObject(cipher)

              RxBiometric
                .title("title")
                .description("description")
                .negativeButtonText("cancel")
                .negativeButtonListener(DialogInterface.OnClickListener { _, _ ->
                  showMessage("cancel")
                })
                .executor(ActivityCompat.getMainExecutor(this@MainActivity))
                .build()
                .authenticate(this, cryptoObject)
            }
          }
          .observeOn(AndroidSchedulers.mainThread())
          .subscribeBy(
            onNext = {
              showMessage("authenticated! ${it.cryptoObject}")
              if(encoded.isNotEmpty()){
                it.cryptoObject?.cipher?.let { cipher ->
                  val cipherBytes = Base64.decode(encoded, Base64.URL_SAFE)
                  println(">>>> will decode ${cipherBytes.size}, $encoded ${encoded.length}")
                  val out = cipher.doFinal(cipherBytes)
                  val b64 = String(out)
                  println(">>>>> decode $b64")
                  encoded = ""
                  lastIv = ""
                }
              }else {
                it.cryptoObject?.cipher?.let { cipher ->
                  val plaintext = "Hello World Hello World Hello World Hello World Hello World".toByteArray()
                  val out = cipher.doFinal(plaintext)
                  val b64 = Base64.encodeToString(out, Base64.URL_SAFE)
                  encoded = b64
                  lastIv = Base64.encodeToString(cipher.iv, Base64.URL_SAFE)
                  println(">>>>> encode ${out.size} bytes, $b64 ${b64.length}")
                }
              }
            },
            onError = {
              when (it) {
                is AuthenticationError -> showMessage("error: ${it.errorCode} ${it.errorMessage}")
                is AuthenticationFail -> showMessage("fail")
                else -> {
                  it.printStackTrace()
                  showMessage("other error")
                }
              }
            }
          )
    }

    encryptBtn.setOnClickListener {
      var keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        .apply {
          val builder = KeyGenParameterSpec.Builder("KUNG KEY",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
          val keySpec = builder.setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(5 * 60)
            .build()
          init(keySpec)
        }
      val keypair = keyGenerator.generateKey()
      val cipher = Cipher.getInstance(
        KeyProperties.KEY_ALGORITHM_AES + "/"
          + KeyProperties.BLOCK_MODE_CBC + "/"
          + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .apply { init(Cipher.ENCRYPT_MODE, keypair) }
      var cryptoObject = BiometricPrompt.CryptoObject(cipher)

      val plaintext = "Hello World".toByteArray()
      val out = cipher.doFinal(plaintext)
      val b64 = Base64.encodeToString(out, Base64.URL_SAFE)
      println(">>>>> $b64")
    }
  }

  @RequiresApi(Build.VERSION_CODES.M)
  fun getAESKey(keyAlias: String) :SecretKey {
    val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
    androidKeyStore.load(null)
    if(androidKeyStore.containsAlias(keyAlias)){
      return androidKeyStore.getKey(keyAlias, null) as SecretKey
    }


    var keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
      .apply {
        val builder = KeyGenParameterSpec.Builder(keyAlias,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        val keySpec = builder.setKeySize(256)
          .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
          .setRandomizedEncryptionRequired(true)
          .setUserAuthenticationRequired(true)
          .setUserAuthenticationValidityDurationSeconds(5 * 60)
          .build()
        init(keySpec)
      }
    return keyGenerator.generateKey()
  }


  override fun onPause() {
    super.onPause()
    disposable?.let {
      if (!it.isDisposed) {
        it.dispose()
      }
    }
  }

  private fun showMessage(message: String) {
    Toast
      .makeText(
        this@MainActivity,
        message,
        Toast.LENGTH_SHORT
      )
      .show()
  }
}