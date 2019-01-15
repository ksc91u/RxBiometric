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
package com.github.pwittchen.rxbiometric.library

import android.annotation.SuppressLint
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationCallback
import androidx.biometric.BiometricPrompt.CryptoObject
import androidx.core.app.ActivityCompat
import androidx.fragment.app.FragmentActivity
import io.reactivex.Single
import io.reactivex.SingleEmitter

class RxBiometric(val promptInfo: BiometricPrompt.PromptInfo) {

  companion object {

    @JvmStatic
    fun build(
      builder: RxBiometricBuilder
    ): RxBiometric {
      return RxBiometric(BiometricPrompt.PromptInfo.Builder()
        .setTitle(builder.title)
        .setDescription(builder.description)
        .setNegativeButtonText(builder.negativeButtonText).build()
      )
    }
  }

  fun authenticate(activity: FragmentActivity): Single<BiometricPrompt.AuthenticationResult> {
    return Single.create { emitter ->
      createPrompt(activity, emitter).authenticate(promptInfo)
    }
  }

  fun authenticate(
    activity: FragmentActivity,
    cryptoObject: CryptoObject
  ): Single<BiometricPrompt.AuthenticationResult> {
    return Single.create { emitter ->
      createPrompt(activity, emitter).authenticate(
        promptInfo,
        cryptoObject
      )
    }
  }

  @SuppressLint("NewApi")
  fun createPrompt(
    activity: FragmentActivity,
    emitter: SingleEmitter<BiometricPrompt.AuthenticationResult>
  ): BiometricPrompt {
    return BiometricPrompt(activity,
      ActivityCompat.getMainExecutor(activity),
      createAuthenticationCallback(emitter)
    )
  }

  private fun createAuthenticationCallback(
    emitter: SingleEmitter<BiometricPrompt.AuthenticationResult>
  ): AuthenticationCallback {
    return Authentication().createAuthenticationCallback(emitter)
  }
}