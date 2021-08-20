/*
 * Copyright 2019 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.fido2.ui.home

import android.app.PendingIntent
import android.content.Intent
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.map
import com.example.android.fido2.repository.AuthRepository
import com.example.android.fido2.repository.SignInState
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val repository: AuthRepository
) : ViewModel() {

    private val _processing = MutableLiveData<Boolean>()
    val processing: LiveData<Boolean>
        get() = _processing

    val currentUsername: LiveData<String> = repository.getSignInState().map { state ->
        when (state) {
            is SignInState.SigningIn -> state.username
            is SignInState.SignedIn -> state.username
            else -> "User"
        }
    }

    val credentials = repository.getCredentials()

    fun reauth() {
        repository.clearCredentials()
    }

    fun signOut() {
        repository.signOut()
    }

    fun registerRequest(): LiveData<PendingIntent?> {
        return repository.registerRequest(_processing)
    }

    fun registerResponse(credential: PublicKeyCredential) {
        repository.registerResponse(credential, _processing)
    }

    fun removeKey(credentialId: String) {
        repository.removeKey(credentialId, _processing)
    }

}
