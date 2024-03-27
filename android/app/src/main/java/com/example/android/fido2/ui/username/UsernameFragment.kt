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

import android.app.Activity
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import com.example.android.fido2.R
import com.example.android.fido2.databinding.UsernameFragmentBinding
import com.example.android.fido2.utils.ApiResponse
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.collectLatest

@AndroidEntryPoint
class UsernameFragment : Fragment() {

    private val viewModel: UsernameViewModel by viewModels()
    private lateinit var binding: UsernameFragmentBinding

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        binding = UsernameFragmentBinding.inflate(inflater, container, false)
        binding.lifecycleOwner = viewLifecycleOwner
        binding.viewModel = viewModel
        return binding.root
    }

    private val createCredentialIntentLauncher = registerForActivityResult(
        ActivityResultContracts.StartIntentSenderForResult(),
        ::handleCreateCredentialResult
    )

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        viewLifecycleOwner.lifecycleScope.launchWhenStarted {
            viewModel.sending.collect { sending ->
                if (sending) {
                    binding.sending.show()
                } else {
                    binding.sending.hide()
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launchWhenStarted {
            viewModel.pendingIntent.collectLatest { result ->
                when (result) {
                    is ApiResponse.Error -> {
                        Toast.makeText(requireContext(), "${result.errorMessage}", Toast.LENGTH_SHORT).show()
                    }
                    ApiResponse.Loading -> {}
                    is ApiResponse.Success -> {
                        if (result.data != null) {
//                            Toast.makeText(requireContext(), "IntentLaunched", Toast.LENGTH_SHORT).show()
                            createCredentialIntentLauncher.launch(
                                IntentSenderRequest.Builder(result.data).build()
                            )
                        }
                    }
                }
            }
        }


        binding.next.setOnClickListener {
            validateTwoInputField()
        }

        binding.login.setOnClickListener {
            viewModel.redirectToLogin()
        }

    }

    private fun handleCreateCredentialResult(activityResult: ActivityResult) {
        val bytes = activityResult.data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
        when {
            activityResult.resultCode != Activity.RESULT_OK ->
                Toast.makeText(requireContext(), R.string.cancelled, Toast.LENGTH_LONG).show()

            bytes == null ->
                Toast.makeText(requireContext(), R.string.credential_error, Toast.LENGTH_LONG)
                    .show()

            else -> {
                val credential = PublicKeyCredential.deserializeFromBytes(bytes)
                val response = credential.response
                if (response is AuthenticatorErrorResponse) {
                    Toast.makeText(requireContext(), "${response.errorMessage} code ${response.errorCode}", Toast.LENGTH_LONG).show()
                } else {
                    var name = binding.name.editText?.text.toString().trim()
                    Toast.makeText(requireContext(), "LoggedIn $name", Toast.LENGTH_SHORT).show()
                    viewModel.registerBiometricResponse(credential, name)
                }
            }
        }
    }

    private fun validateTwoInputField() {
        var name = binding.name.editText?.text.toString().trim()
        var username = binding.username.editText?.text.toString().trim()

        if (name.isNotBlank() && username.isNotBlank()) {
            viewModel.registerUser(name, username)
        } else if (name.isBlank()) {
            Toast.makeText(requireContext(), "Please enter name", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(requireContext(), "Please enter username", Toast.LENGTH_SHORT).show()
        }
    }

}
