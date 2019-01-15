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
import android.content.SharedPreferences
import android.os.Bundle
import android.preference.PreferenceManager
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import io.reactivex.disposables.Disposable
import io.reactivex.rxkotlin.subscribeBy
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*
import javax.crypto.BadPaddingException

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
      secureKey = SecureKey("SomeNewKey", this@MainActivity).apply {
        initBiometrics(this@MainActivity)
        val encBytes = encryptWithPasscode("wdlkjflwkejfl", "Hello World AES".toByteArray())
        try {
          val clearBytes = decryptWithPasscode("wdlkjflwkejfl", encBytes)
          println(">>>>> " + String(clearBytes))
          val wrong = decryptWithPasscode("djfslksd", encBytes)
        } catch (e: BadPaddingException) {
          println(">>>>> decrypt with wrong password failed")
        }
      }

    }

    encryptBtn.setOnClickListener {
      secureKey?.let{ key ->
        key.encryptWithBiometrics(this, "Hello World".toByteArray()).subscribeBy(onSuccess = {
          this@MainActivity.lastIv = Base64.encodeToString(it.second, Base64.URL_SAFE)
          this@MainActivity.encoded = Base64.encodeToString(it.first, Base64.URL_SAFE)
        }, onError = {
          it.printStackTrace()
        })

      }
    }

    decryptBtn.setOnClickListener {
      val iv = Base64.decode(this.lastIv, Base64.URL_SAFE)
      val encBytes = Base64.decode(this.encoded, Base64.URL_SAFE)
      secureKey?.decryptWithBiometrics(this, Pair(encBytes, iv))?.subscribeBy( onSuccess= {
        println(">>>> decrypted " + String(it))
      }, onError = {
        it.printStackTrace()
      })
    }
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