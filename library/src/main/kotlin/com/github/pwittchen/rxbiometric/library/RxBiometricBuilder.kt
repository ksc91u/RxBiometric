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

import android.content.DialogInterface

class RxBiometricBuilder {
  internal lateinit var title: String
  internal lateinit var description: String
  internal lateinit var negativeButtonText: String
  internal lateinit var negativeButtonListener: DialogInterface.OnClickListener

  fun title(title: String): RxBiometricBuilder {
    this.title = title
    return this
  }

  fun description(description: String): RxBiometricBuilder {
    this.description = description
    return this
  }

  fun negativeButtonText(negativeButtonText: String): RxBiometricBuilder {
    this.negativeButtonText = negativeButtonText
    return this
  }

  fun negativeButtonListener(negativeButtonListener: DialogInterface.OnClickListener): RxBiometricBuilder {
    this.negativeButtonListener = negativeButtonListener
    return this
  }

  fun build(): RxBiometric {
    return RxBiometric.build(this)
  }
}