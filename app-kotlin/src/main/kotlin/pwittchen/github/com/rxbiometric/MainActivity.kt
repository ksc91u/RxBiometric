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

import android.annotation.SuppressLint
import android.content.DialogInterface
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.preference.PreferenceDataStore
import android.preference.PreferenceManager
import android.security.KeyPairGeneratorSpec
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
import java.math.BigInteger
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal

/*
*
* M 以上 -> Biometrics 256bits AES Key
*                                             ====> 256bits AES Key
*       -> Passcode + Keystore RSA( AES Key)
* */

class MainActivity : AppCompatActivity() {

  private var disposable: Disposable? = null

  private var encoded: String = ""

  private var lastIv: String = ""

  private lateinit var sharedPreference: SharedPreferences

  private var secureKey: SecureKey? = null

  @SuppressLint("NewApi")
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    setSupportActionBar(toolbar)

    sharedPreference = PreferenceManager.getDefaultSharedPreferences(this)


    button.setOnClickListener { _ ->
      secureKey = SecureKey("", "SomeNewKey").apply {
        initBiometrics(this@MainActivity)
      }
    }

    encryptBtn.setOnClickListener {
      secureKey?.encryptWithBiometrics(this, "Hello World".toByteArray()).subscribe{
        if(it == null) {
          return@subscribe
        }
        this@MainActivity.lastIv = Base64.encodeToString(it.second, Base64.URL_SAFE)
        this@MainActivity.encoded = Base64.encodeToString(it.first, Base64.URL_SAFE)
      }
    }

    decryptBtn.setOnClickListener {
      val iv = Base64.decode(this.lastIv, Base64.URL_SAFE)
      val encBytes = Base64.decode(this.encoded, Base64.URL_SAFE)
      secureKey?.decryptWithBiometrics(this, Pair(encBytes, iv)).subscribe{
        if(it ==  null){
          return@subscribe
        }
        println(">>>> decrypted " + String(it))
      }
    }
  }


  /*fun getAESKey(keyAlias: String, password: String): SecretKey? {
    val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
    androidKeyStore.load(null)
    if (androidKeyStore.containsAlias(keyAlias)) {
      val pair = androidKeyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
      println(">>>>> private key get ")
      println(">>>>> private key " + pair.privateKey)

      var cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA + "/"
        + KeyProperties.BLOCK_MODE_ECB + "/"
        + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
      var triple = getAESKeyEncrypted()

      triple?.let {
        cipher.init(Cipher.DECRYPT_MODE, pair.privateKey)
        val aes1 = cipher.doFinal(it.first)
        val aes2 = cipher.doFinal(it.second)
        println(">>>> get aes key "+ Base64.encodeToString(aes1, Base64.URL_SAFE) + "/" + Base64.encodeToString(aes2, Base64.URL_SAFE))
      }


      return null
    }

    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
    val keySpec = KeyPairGeneratorSpec.Builder(this@MainActivity)
      .setAlias(keyAlias)
      .setKeyType(KeyProperties.KEY_ALGORITHM_RSA)
      .setKeySize(2048)
      .setSubject(X500Principal("CN=mobidick"))
      .setSerialNumber(BigInteger.ONE)
      .setStartDate(Date(1970, 1, 1, 1, 1, 1))
      .setEndDate(Date(2100, 1, 1, 1, 1, 1))
      .build()
    kpg.initialize(keySpec)
    val pair = kpg.genKeyPair()
    println(">>>>> private key generated ")
    println(">>>>> private key " + pair.private)


    if (getAESKeyEncrypted() == null) {
      var sr = SecureRandom()
      var iv = sr.generateSeed(12)
      var aes0 = ByteArray(16)
      var aes1 = ByteArray(16)
      sr.nextBytes(aes0)
      sr.nextBytes(aes1)

      var cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA + "/"
        + KeyProperties.BLOCK_MODE_ECB + "/"
        + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)

      cipher.init(Cipher.ENCRYPT_MODE, pair.public)

      setAESKeyEncrypted(cipher.doFinal(aes0), cipher.doFinal(aes1), iv)

      println(">>>> generate aes key " + Base64.encodeToString(aes0, Base64.URL_SAFE) + "/" + Base64.encodeToString(aes1, Base64.URL_SAFE))
    }



    return null
  }*/


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