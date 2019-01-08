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
package com.github.pwittchen.rxbiometric.library.validation

import android.content.Context
import io.reactivex.Single

class RxPreconditions {
  companion object {
    @JvmStatic fun hasBiometricSupport(context: Context): Single<Boolean> {
      return Single.just(Preconditions.hasBiometricSupport(context))
    }

    @JvmStatic fun isAtLeastAndroidPie(): Single<Boolean> {
      return Single.just(Preconditions.isAtLeastAndroidPie())
    }

    @JvmStatic fun canHandleBiometric(context: Context): Single<Boolean> {
//      return hasBiometricSupport(context).flatMap { it ->
//        if (it) isAtLeastAndroidPie()
//        else Single.just(false)
//      }
      return Single.just(true)
    }
  }
}