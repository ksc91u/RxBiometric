package pwittchen.github.com.rxbiometric

import android.content.Context
import android.content.DialogInterface
import android.os.Build
import android.preference.PreferenceManager
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
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
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

class SecureKey(private val passcode: String, private val keyName: String, private val context: Context) {

  companion object {
    val KEY_ALGORITHM_RSA = "RSA"

    val AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding"
    val RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding"
    val AES = "AES"

  }

  var aes_part0: ByteArray = ByteArray(16)
  var aes_part1: ByteArray = ByteArray(16)
  val secureRandom = SecureRandom()
  val disposable: CompositeDisposable = CompositeDisposable()
  var secretKey: SecretKey? = null
  var rsaPrivate: PrivateKey? = null
  var rsaPublic: PublicKey? = null

  init {
    initRsaKey()
    initAesKey()
  }

  protected fun finalize() {
    disposable.dispose()
  }

  fun initAesKey() {
    val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)

    if (sharedPreferences.contains("aes_0_$keyName") && sharedPreferences.contains("aes_1_$keyName")) {
      val aes0 = sharedPreferences.getString("aes_0_$keyName", "")
      val aes1 = sharedPreferences.getString("aes_1_$keyName", "")
      var rsaDecCipher = Cipher.getInstance(RSA_ECB_PKCS1).apply {
        init(Cipher.DECRYPT_MODE, rsaPrivate)
      }

      aes_part0 = rsaDecCipher.doFinal(Base64.decode(aes0, Base64.NO_PADDING))
      aes_part1 = rsaDecCipher.doFinal(Base64.decode(aes1, Base64.NO_PADDING))
      return
    }


    sharedPreferences.edit().remove("aes_0_$keyName").remove("aes_1_$keyName").apply()

    secureRandom.nextBytes(aes_part0)
    secureRandom.nextBytes(aes_part1)

    var rsaEncCipher = Cipher.getInstance(RSA_ECB_PKCS1).apply {
      init(Cipher.ENCRYPT_MODE, rsaPublic)
    }

    val aes0 = Base64.encodeToString(rsaEncCipher.doFinal(aes_part0), Base64.NO_PADDING)
    val aes1 = Base64.encodeToString(rsaEncCipher.doFinal(aes_part1), Base64.NO_PADDING)
    sharedPreferences.edit().putString("aes_0_$keyName", aes0).putString("aes_1_$keyName", aes1).apply()

  }

  fun initRsaKey() {
    val rsaKeyName = "RSA_$keyName"
    val androidKeyStore = KeyStore.getInstance("AndroidKeyStore")
    androidKeyStore.load(null)
    if (androidKeyStore.containsAlias(rsaKeyName)) {
      rsaPrivate = (androidKeyStore.getEntry(rsaKeyName, null) as KeyStore.PrivateKeyEntry).privateKey

      return
    }

    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
    val keySpec = KeyPairGeneratorSpec.Builder(context)
      .setAlias(rsaKeyName)
      .setKeyType(KeyProperties.KEY_ALGORITHM_RSA)
      .setKeySize(3072)
      .setSubject(X500Principal("CN=mobidick"))
      .setSerialNumber(BigInteger.ONE)
      .setStartDate(Date(1970, 1, 1, 1, 1, 1))
      .setEndDate(Date(2100, 1, 1, 1, 1, 1))
      .build()
    kpg.initialize(keySpec)
    val pair = kpg.genKeyPair()
    rsaPrivate = pair.private
    rsaPublic = pair.public
  }

  @RequiresApi(Build.VERSION_CODES.M)
  fun decryptWithBiometrics(activity: FragmentActivity, encryptTextAndIv: Pair<ByteArray, ByteArray>): Observable<ByteArray?> {
    if (secretKey == null) {
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
        if (authResult.cryptoObject == null) {
          return@map null
        } else {
          val cipher = authResult.cryptoObject!!.cipher!!
          val result = cipher.doFinal(encryptTextAndIv.first)
          return@map result
        }
      }
  }

  /* insecure aes encoding, should use SecretKeyFactory */
  fun encryptWithPasscode(clearTextBytes: ByteArray): ByteArray {
    var iv = ByteArray(16)
    secureRandom.nextBytes(iv)

    val skeySpec = SecretKeySpec(aes_part0.sliceArray(IntRange(0, 15)), AES)
    val cipher = Cipher.getInstance(AES_CBC_PKCS5)
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, IvParameterSpec(iv))
    return iv + cipher.doFinal(clearTextBytes)
  }

  fun decryptWithPasscode(encTextBytes: ByteArray): ByteArray {
    val skeySpec = SecretKeySpec(aes_part0.sliceArray(IntRange(0, 15)), AES)
    val cipher = Cipher.getInstance(AES_CBC_PKCS5)
    val iv = encTextBytes.sliceArray(IntRange(0, 15))
    val enc = encTextBytes.sliceArray(IntRange(16, encTextBytes.size - 1))
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, IvParameterSpec(iv))
    return cipher.doFinal(enc)
  }

  @RequiresApi(Build.VERSION_CODES.M)
  fun encryptWithBiometrics(activity: FragmentActivity, clearTextBytes: ByteArray): Observable<Pair<ByteArray, ByteArray>?> {
    if (secretKey == null) {
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
        if (authResult.cryptoObject == null) {
          return@map null
        } else {
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