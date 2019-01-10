package pwittchen.github.com.rxbiometric

import android.content.DialogInterface
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.fragment.app.FragmentActivity
import com.github.pwittchen.rxbiometric.library.RxBiometric
import com.github.pwittchen.rxbiometric.library.validation.RxPreconditions
import io.reactivex.Observable
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.rxkotlin.addTo
import io.reactivex.rxkotlin.subscribeBy
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class SecureKey(private val passcode: String, private val keyName: String) {

  var aes_part0: ByteArray = ByteArray(16)
  var aes_part1: ByteArray = ByteArray(16)
  val secureRandom = SecureRandom()
  val disposable:CompositeDisposable = CompositeDisposable()
  var secretKey: SecretKey? = null

  init {
    secureRandom.nextBytes(aes_part0)
    secureRandom.nextBytes(aes_part1)
  }

  protected fun finalize() {
    disposable.dispose()
  }

  @RequiresApi(Build.VERSION_CODES.M)
  fun decryptWithBiometrics(activity: FragmentActivity, encryptTextAndIv : Pair<ByteArray, ByteArray> ) : Observable<ByteArray?>{
    if(secretKey == null){
      Toast.makeText(activity, "Run initBiometrics first", Toast.LENGTH_LONG).show()
      return Observable.error(IllegalStateException("Run initBiometrics first"))
    }
    val cipher = Cipher.getInstance(
      KeyProperties.KEY_ALGORITHM_AES + "/"
        + KeyProperties.BLOCK_MODE_CBC + "/"
        + KeyProperties.ENCRYPTION_PADDING_PKCS7)
      .apply {
        init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(encryptTextAndIv.second))
      }
    var cryptoObject = BiometricPrompt.CryptoObject(cipher)
    return RxBiometric
      .title("Decrypt")
      .description("Decrypt")
      .negativeButtonText("cancel")
      .negativeButtonListener(DialogInterface.OnClickListener { p0, p1 ->
      })
      .executor(ActivityCompat.getMainExecutor(activity))
      .build()
      .authenticate(activity, cryptoObject)
      .observeOn(AndroidSchedulers.mainThread())
      .map { authResult ->
        if(authResult.cryptoObject == null){
          return@map null
        }else{
          val cipher = authResult.cryptoObject!!.cipher!!
          val result = cipher.doFinal(encryptTextAndIv.first)
          return@map result
        }
      }
  }

  @RequiresApi(Build.VERSION_CODES.M)
  fun encryptWithBiometrics(activity: FragmentActivity, clearTextBytes: ByteArray) : Observable<Pair<ByteArray, ByteArray>?>{
    if(secretKey == null){
      Toast.makeText(activity, "Run initBiometrics first", Toast.LENGTH_LONG).show()
      return Observable.error(IllegalStateException("Run initBiometrics first"))
    }
    val cipher = Cipher.getInstance(
      KeyProperties.KEY_ALGORITHM_AES + "/"
        + KeyProperties.BLOCK_MODE_CBC + "/"
        + KeyProperties.ENCRYPTION_PADDING_PKCS7)
      .apply {
        init(Cipher.ENCRYPT_MODE, secretKey)
      }
    var cryptoObject = BiometricPrompt.CryptoObject(cipher)
    return RxBiometric
      .title("Encrypt")
      .description("Encrypt")
      .negativeButtonText("cancel")
      .negativeButtonListener(DialogInterface.OnClickListener { p0, p1 ->
      })
      .executor(ActivityCompat.getMainExecutor(activity))
      .build()
      .authenticate(activity, cryptoObject)
      .observeOn(AndroidSchedulers.mainThread())
      .map { authResult ->
        if(authResult.cryptoObject == null){
          return@map null
        }else{
          val cipher = authResult.cryptoObject!!.cipher!!
          val result = cipher.doFinal(clearTextBytes)
          val iv = cipher.iv
          return@map Pair(result, iv)
        }
      }
  }



  @RequiresApi(Build.VERSION_CODES.M)
  fun initBiometrics(acvitity: FragmentActivity) {
    RxPreconditions.canHandleBiometric(acvitity)
      .observeOn(AndroidSchedulers.mainThread())
      .subscribeBy {
        if (!it) {
          Toast.makeText(acvitity, "No Biometrics Support", Toast.LENGTH_LONG).show()
        } else {
          secretKey = getAESKey(keyName)
        }
      }.addTo(disposable)
  }

  @RequiresApi(Build.VERSION_CODES.M)
  fun getAESKey(keyAlias: String): SecretKey {
    val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
    androidKeyStore.load(null)
    if (androidKeyStore.containsAlias(keyAlias)) {
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
}