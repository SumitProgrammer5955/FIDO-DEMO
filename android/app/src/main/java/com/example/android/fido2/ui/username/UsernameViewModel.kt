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

package com.example.android.fido2.ui.username

import android.app.PendingIntent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.android.fido2.repository.AuthRepository
import com.example.android.fido2.utils.ApiResponse
import com.google.android.gms.common.api.Api
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class UsernameViewModel @Inject constructor(
    private val repository: AuthRepository
) : ViewModel() {

    private val _sending = MutableStateFlow(false)
    val sending = _sending.asStateFlow()

    private val _pendingIntent = MutableStateFlow<ApiResponse<PendingIntent?>>(ApiResponse.Loading)
    val pendingIntent = _pendingIntent.asStateFlow()


    fun registerUser(name: String, username: String) {
        viewModelScope.launch {
            _sending.value = true
            try {
                val result = repository.registerUser(name, username)
                when (result) {
                    is ApiResponse.Error -> {
                        _pendingIntent.value = ApiResponse.Error(result.errorMessage)
                    }
                    ApiResponse.Loading ->  {
                        _pendingIntent.value = ApiResponse.Loading
                    }
                    is ApiResponse.Success -> {
                        _pendingIntent.value = ApiResponse.Success(result.data)
                    }
                }
            } finally {
                _sending.value = false
            }
        }
    }

    fun registerBiometricResponse(credential: PublicKeyCredential, name: String) {
        viewModelScope.launch {
            _sending.value = true
            try {
                repository.registerResponse(credential, name)
            } finally {
                _sending.value = false
            }
        }
    }

    fun redirectToLogin() {
        viewModelScope.launch {
            repository.redirectToLogin()
        }
    }

}
